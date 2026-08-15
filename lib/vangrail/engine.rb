# frozen_string_literal: true

require_relative 'errors'
require_relative 'evidence'
require_relative 'evidence_data'
require_relative 'judgement'
require_relative 'rail'
require_relative 'result'
require_relative 'result_cache'

module Vangrail
  # Runs ordered rails over text and reports one Result.
  #
  # The rules are short enough to state in full:
  #
  # - Rails run in the order given. The first :blocked ends the pass.
  # - A :modified result replaces the text for every rail after it, and the
  #   engine reports :modified unless something later blocks.
  # - A rail that raises is not a rail that passed. `on_error: :allow` (the
  #   default) keeps going and marks the pass uncertain; `:block` stops.
  # - An empty rail list returns :passed with certain false. Nothing ran.
  #
  # Threading rewrites through later rails is the part worth being explicit
  # about: a redaction rail that runs before a policy rail should have the
  # policy rail judge the redacted text, not the original.
  class Engine
    attr_reader :input_rails, :context_rails, :output_rails, :on_error, :cache

    def initialize(input: [], context: [], output: [], on_error: :allow, cache: true)
      @input_rails = Array(input)
      @context_rails = Array(context)
      @output_rails = Array(output)
      @on_error = on_error.to_sym
      raise ArgumentError, 'on_error must be :allow or :block' unless %i[allow block].include?(@on_error)

      @cache = cache.is_a?(ResultCache) ? cache : (ResultCache.new if cache)
    end

    def check_input(text, context = {})
      run(:input, input_rails, text, context)
    end

    def check_output(text, user_input: nil, passages: nil, **context)
      run(:output, output_rails, text, context.merge(user_input: user_input, passages: passages))
    end

    # One retrieved document, before it goes anywhere near a prompt.
    def check_context(text, **context)
      run(:context, context_rails, text, context)
    end

    # Screens a set of retrieved documents and reports what survived.
    #
    # A document that fails is dropped rather than failing the whole turn. One
    # poisoned wiki page should cost a reader that page, not their answer, and
    # an application that refuses outright teaches its readers that the
    # guardrail is the problem.
    def screen(documents, **context)
      kept = []
      rejected = []
      uncertain = nil

      Array(documents).each_with_index do |document, index|
        result = check_context(text_of(document), **context, document: document, index: index)
        uncertain ||= result unless result.certain?
        if result.blocked?
          rejected << { document: document, result: result }
        else
          kept << (result.modified? ? replace_text(document, result.content) : document)
        end
      end

      Screening.new(kept: kept, rejected: rejected, certain: uncertain.nil?, reason: uncertain&.reason)
    end

    # What screen returns. `certain` means what it means on a Result: false says
    # a rail did not reach a decision about some document, so "nothing was
    # rejected" is not evidence that nothing was wrong.
    Screening = Struct.new(:kept, :rejected, :certain, :reason, keyword_init: true) do
      def certain?
        certain
      end

      def rejected?
        !rejected.empty?
      end

      def to_h
        {
          'kept' => kept.size,
          'rejected' => rejected.map { |r| r[:result].to_h },
          'certain' => certain?,
          'reason' => reason
        }.compact
      end
    end

    # How likely is it that this text is an attack, given everything that ran.
    #
    # `check_input` and friends answer a different question. They run the rails
    # in order, stop at the first block, and report a decision; that is the
    # right shape for a request path and it is what every published defence
    # does. It also throws away most of what was measured. A rail that fired
    # tells you nothing about how much that hit is worth, three rails that
    # nearly fired tell you nothing at all, and a block carries no number an
    # operator can set a policy against.
    #
    # This runs every rail that has a measured operating point, treats each
    # verdict as evidence, and combines it with the deployment's base rate.
    # What comes back is a probability, the bits each rail contributed, and an
    # action under a stated policy.
    #
    # The prior is not optional and has no sensible default. Detector papers
    # report their numbers on balanced corpora, where an attack is half the
    # traffic; a documentation desk over an editable wiki might see one poisoned
    # page in ten thousand. Those two worlds disagree about what a hit means by
    # four orders of magnitude, and only the deployment knows which one it is
    # in. Guessing on its behalf would be the whole error this method exists to
    # expose.
    #
    #   judgement = engine.assess(page, side: :context, prior: 1e-4)
    #   judgement.posterior    # => 0.0073
    #   judgement.action       # => :review
    #   judgement.fired        # => [{rail: "paraphrase", bits: 6.2, ...}]
    #
    # Costs more than a check, because nothing short-circuits: every rail with
    # an entry in the table runs, including the ones a block would have skipped.
    def assess(text, side: :input, prior: nil, policy: Policy::DEFAULT, evidence: EvidenceData::TABLE,
               **context)
      raise ArgumentError, prior_message if prior.nil?

      observations, certain = observe(text, side, context, evidence)
      posterior, contributions = Posterior.combine(prior: prior, observations: observations,
                                                   evidence: evidence)
      Judgement.new(posterior: posterior, prior: prior, bits: contributions.sum { |c| c[:bits] },
                    contributions: contributions, certain: certain, side: side.to_sym,
                    action: policy.action_for(posterior))
    end

    def rails(side)
      case side.to_sym
      when :input then input_rails
      when :context then context_rails
      else output_rails
      end
    end

    def rail_names(side)
      rails(side).map(&:name)
    end

    # True when every configured rail decides without a network call, which is
    # the only case where an unreachable endpoint cannot weaken the check.
    def offline?
      all = input_rails + context_rails + output_rails
      !all.empty? && all.all?(&:offline?)
    end

    def empty?
      input_rails.empty? && context_rails.empty? && output_rails.empty?
    end

    def to_h
      {
        'input' => rail_names(:input),
        'context' => (rail_names(:context) unless context_rails.empty?),
        'output' => rail_names(:output),
        'on_error' => on_error.to_s,
        'offline' => offline?,
        'cache' => cache&.to_h
      }.compact
    end

    def describe
      return 'no rails' if empty?

      parts = []
      parts << "input=#{rail_names(:input).join('+')}" unless input_rails.empty?
      parts << "context=#{rail_names(:context).join('+')}" unless context_rails.empty?
      parts << "output=#{rail_names(:output).join('+')}" unless output_rails.empty?
      parts << "on_error=#{on_error}"
      parts << 'offline' if offline?
      parts.join(' ')
    end

    private

    # Runs every rail with a measured operating point and records what each one
    # saw: true for a hit, false for a rail that ran and did not fire, and
    # nothing at all for a rail that could not decide.
    #
    # That third case is the one this gem can express and a pure detector stack
    # cannot. An unreachable rail is not a rail that found nothing, and folding
    # the two together silently converts a broken endpoint into evidence of
    # innocence.
    def observe(text, side, context, evidence)
      ctx = context.merge(side: side)
      body = text.to_s
      certain = true
      observations = {}

      rails(side).each do |rail|
        next unless rail.applies_to?(side)
        next unless evidence[rail.name]&.measured?

        result = invoke(rail, body, ctx)
        if result.certain?
          observations[rail.name] = result.blocked?
        else
          certain = false
        end
      end

      [observations, certain]
    end

    def prior_message
      'assess needs a prior: the share of texts on this side that are actually attacks. ' \
        'Published detector numbers assume a balanced corpus (0.5); a documentation desk over ' \
        'an editable wiki is nearer 1e-4. The answer changes the verdict, and only you know it.'
    end

    def text_of(document)
      return document.to_s unless document.is_a?(Hash)

      (document['text'] || document[:text]).to_s
    end

    # A context rail may rewrite a document rather than reject it, so the
    # replacement has to go back into the shape the caller passed in.
    def replace_text(document, content)
      return content.to_s unless document.is_a?(Hash)

      key = document.key?('text') ? 'text' : :text
      document.merge(key => content.to_s)
    end

    def run(side, rails, text, context)
      return Result.unchecked(rail: side, reason: "no #{side} rails configured") if rails.empty?

      ctx = context.merge(side: side)
      current = text.to_s
      modified_by = nil
      uncertain = nil
      unbuilt = nil

      rails.each do |rail|
        next unless rail.applies_to?(side)

        result = invoke(rail, current, ctx)
        return result.with_rail(rail.name) if result.blocked?

        if result.modified?
          current = result.content_or(current)
          modified_by = rail.name
        end
        next if result.certain?

        # A rail that ran and could not decide says more than one that was
        # never built, so its reason is the one the caller sees. Without this,
        # a placeholder earlier in the list reports "no endpoint was resolved"
        # over the rail that actually tried and had the connection refused.
        if rail.placeholder?
          unbuilt ||= result
        else
          uncertain ||= result
        end
      end

      finish(side, current, modified_by, uncertain || unbuilt)
    end

    def finish(side, current, modified_by, uncertain)
      if modified_by
        return Result.modified(rail: modified_by, content: current,
                               certain: uncertain.nil?, reason: uncertain&.reason)
      end
      return Result.unchecked(rail: uncertain.rail || side, reason: uncertain.reason) if uncertain

      Result.passed(rail: side)
    end

    def invoke(rail, text, ctx)
      memoized(rail, text, ctx) { call_rail(rail, text, ctx) }
    end

    def call_rail(rail, text, ctx)
      result = rail.call(text, ctx)
      return result if result.is_a?(Result)

      raise ProtocolError, "#{rail.name} returned #{result.class}, expected Vangrail::Result"
    rescue Error => e
      failed(rail, e)
    end

    # A rail that raised did not answer. Which way that falls is the operator's
    # call, and either way the pass carries the reason rather than a silence.
    def failed(rail, error)
      reason = "#{rail.name} failed: #{error.class.name.split('::').last}: #{error.message}"
      if on_error == :block
        return Result.new(status: :blocked, rail: rail.name, certain: false,
                          reason: reason)
      end

      Result.unchecked(rail: rail.name, reason: reason)
    end

    # Cache keys carry everything the decision depends on. A rail says what that
    # is through `cache_key`; nil means the rail is not memoizable, which is the
    # right answer for anything reading passages or history.
    def memoized(rail, text, ctx, &block)
      return block.call unless cache

      key = rail.respond_to?(:cache_key) ? rail.cache_key(text, ctx) : nil
      return block.call if key.nil?

      cache.fetch(ctx[:side], rail.name, key, &block)
    end
  end
end
