# frozen_string_literal: true

require_relative 'errors'
require_relative 'evidence'
require_relative 'evidence_data'
require_relative 'judgement'
require_relative 'origin'
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

      def cells
        kept.map { |document| Cell.data(Cell.text_of(document)) }
      end

      def to_h
        {
          'kept' => kept.size,
          'rejected' => rejected.map { |r| r[:result].to_h },
          'certain' => certain?,
          'reason' => reason,
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
    def assess(text, side: :input, prior: nil, policy: Policy::DEFAULT, evidence: nil,
               escalate: false, confidence: Posterior::DEFAULT_CONFIDENCE, origin: nil, **context)
      raise ArgumentError, prior_message if prior.nil?

      origin = Origin.coerce(origin || Origin.default_for(side))
      # A rail is worth different evidence on different sides, by a lot: the
      # same paraphrase rail catches a third of in-the-wild jailbreak prompts
      # and none of the published injections in retrieved documents. One table
      # for both would be an average of two unrelated things.
      evidence ||= EvidenceData.for_side(side)

      observed = observe(text, side, context, evidence, escalate ? { prior: prior, policy: policy } : nil)
      observations, direct, certain, skipped = observed
      posterior, contributions = Posterior.combine(prior: prior, observations: observations,
                                                   evidence: evidence, direct: direct,
                                                   confidence: confidence)
      action = policy.action_for(posterior)
      # A confidence bound is what the corpus can defend. If the point
      # estimate and the bound disagree about the action, the action is not
      # identified: reporting it as a certain decision would spend evidence
      # nobody measured.
      if confidence
        # Explicitly nil, because the bound is what `combine` defaults to now:
        # asking for the point estimate has to say so, or this compares the
        # bound against itself and reports every action as identified.
        point, = Posterior.combine(prior: prior, observations: observations,
                                   evidence: evidence, direct: direct, confidence: nil)
        certain &&= policy.action_for(point) == action
      end
      Judgement.new(posterior: posterior, prior: prior, bits: contributions.sum { |c| c[:bits] },
                    contributions: contributions, certain: certain, side: side.to_sym,
                    skipped: skipped, action: action, origin: origin)
    end

    # Screening, with the documents ranked by how suspicious they are rather
    # than partitioned by whether one rail objected.
    #
    # `screen` drops a document the moment a rail blocks it, which is the right
    # shape when a rail is a switch. Given a posterior there is a better answer
    # available: rank the set, drop what the policy says to drop, hand what it
    # says to review to whoever reviews, and keep the rest. A page that trips
    # one pattern at a base rate of one in ten thousand is not a page worth
    # taking away from a reader, and it is worth putting at the bottom of the
    # passage list.
    #
    #   triage = engine.triage(documents, prior: 1e-4)
    #   triage.keep       # documents, least suspicious first
    #   triage.review     # [{document:, judgement:}]
    #   triage.dropped    # [{document:, judgement:}]
    def triage(documents, prior:, policy: Policy::DEFAULT, escalate: false, **context)
      judged = Array(documents).each_with_index.map do |document, index|
        judgement = assess(text_of(document), side: :context, prior: prior, policy: policy,
                                              escalate: escalate, **context, document: document, index: index)
        { document: document, judgement: judgement }
      end
      Triage.new(judged: judged.sort_by { |row| -row[:judgement].posterior })
    end

    # What triage returns. The ranking is the product: a caller that wants the
    # old behaviour reads `kept`, and one that wants to put the doubtful pages
    # last reads them in order.
    Triage = Struct.new(:judged, keyword_init: true) do
      def dropped
        judged.select { |row| row[:judgement].block? }
      end

      def review
        judged.select { |row| row[:judgement].review? }
      end

      def kept
        judged.reject { |row| row[:judgement].block? }.reverse.map { |row| row[:document] }
      end

      def certain?
        judged.all? { |row| row[:judgement].certain? }
      end

      def to_h
        {
          'kept' => kept.size,
          'review' => review.size,
          'dropped' => dropped.map { |row| row[:judgement].to_h },
          'certain' => certain?,
        }
      end
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
        'cache' => cache&.to_h,
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
    def observe(text, side, context, evidence, escalation = nil)
      ctx = context.merge(side: side)
      body = usable(text)
      certain = true
      observations = {}
      direct = {}
      skipped = []

      queue = rails(side).select do |rail|
        next false unless rail.applies_to?(side)
        next true if rail.posture?
        next true if rail.respond_to?(:quantifies?) && rail.quantifies?

        evidence[rail.name]&.measured?
      end
      # Posture first, so a page nothing can read is known before silence is
      # recorded. Cheap first after that when escalating, so a round trip is
      # what an early stop can save.
      posture, rest = queue.partition(&:posture?)
      rest = rest.partition(&:offline?).flatten if escalation
      queue = posture + rest
      readable = true

      queue.each_with_index do |rail, index|
        if escalation && !rail.posture? && settled?(observations, queue[index..], evidence, escalation)
          skipped = queue[index..].map(&:name)
          break
        end

        result = invoke(rail, body, ctx)
        if rail.posture?
          unless result.certain?
            certain = false
            readable = false
          end
          next
        end

        unless result.certain?
          certain = false
          next
        end

        # A hit still counts: a hidden English injection inside a German
        # page is a hit. Silence does not. A rail that cannot read this
        # language and did not fire has not said the page is clean.
        next unless readable || rail.language_agnostic? || result.blocked?

        # A rail that computed a likelihood ratio reports it in `raw`, and is
        # read that way rather than being flattened to whether it blocked.
        bits = result.raw.is_a?(Hash) ? result.raw['bits'] : nil
        if bits
          direct[rail.name] = bits.to_f
        else
          observations[rail.name] = result.blocked?
        end
      end

      [observations, direct, certain, skipped]
    end

    # Would running the rest change what happens?
    #
    # Not a guess and not a threshold on confidence: the evidence a rail can
    # carry is bounded by its measured operating point, so the most the
    # remaining rails could move the posterior in either direction is a number
    # this can add up. When the action is the same at both ends of that
    # interval, the remaining rails cannot change the outcome and running them
    # buys nothing.
    #
    # This is why the framing pays for itself rather than only being tidier. A
    # documentation desk running the deterministic rails and one model rail
    # pays for the round trip on every check under the switch; here it pays only
    # when the free evidence leaves the answer genuinely open, which on ordinary
    # traffic is almost never.
    #
    # Skipping is not abstention. A rail that was proved irrelevant did not fail
    # to run, so `certain?` stays true: the claim is about the action, and the
    # action is unchanged by construction.
    def settled?(observations, remaining, evidence, escalation)
      return false if remaining.empty?
      # A rail that reports its own likelihood ratio has no bound to reason
      # against: its contribution is whatever the text scores. Nothing is
      # skipped while one of those is still to run.
      return false if remaining.any? { |rail| rail.respond_to?(:quantifies?) && rail.quantifies? }

      posterior, = Posterior.combine(prior: escalation[:prior], observations: observations,
                                     evidence: evidence)
      reachable = remaining.filter_map { |rail| evidence[rail.name] }
      return false if reachable.empty?

      best = reachable.sum { |entry| entry.bits(true) }
      worst = reachable.sum { |entry| entry.bits(false) }
      policy = escalation[:policy]
      odds = Posterior.to_odds(posterior)

      policy.action_for(Posterior.from_odds(odds * (2**best))) ==
        policy.action_for(Posterior.from_odds(odds * (2**worst)))
    end

    def prior_message
      'assess needs a prior: the share of texts on this side that are actually attacks. ' \
        'Published detector numbers assume a balanced corpus (0.5); a documentation desk over ' \
        'an editable wiki is nearer 1e-4. The answer changes the verdict, and only you know it.'
    end

    # Text a rail can actually read.
    #
    # Every pattern rail runs a regexp at this string and every lexicon rail
    # normalises it, and both raise on bytes that are not valid UTF-8:
    # ArgumentError from String#match?, Encoding::CompatibilityError from
    # unicode_normalize on a body still tagged binary. Neither is a
    # Vangrail::Error, so neither reached the on_error path -- the exception
    # went straight through the engine and out of the application's screening
    # call, taking the turn with it.
    #
    # That is an ordinary event rather than an attack. A model's answer is
    # reassembled from network chunks, so a split multi-byte character is
    # normal; a wiki page in a legacy encoding is normal; a body read off a
    # socket arrives tagged ASCII-8BIT whatever is in it.
    #
    # So the bytes are made usable once, here, at the boundary. Everything
    # downstream measures the same scrubbed string, so a rewrite handed back to
    # the caller and the offsets inside it stay consistent with what was
    # judged.
    def usable(text)
      body = text.to_s
      body = body.dup.force_encoding(Encoding::UTF_8) unless body.encoding == Encoding::UTF_8
      body.valid_encoding? ? body : body.scrub
    end

    def text_of(document)
      Cell.text_of(document)
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
      current = usable(text)
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
    rescue ArgumentError, EncodingError => e
      # A rail that could not read the bytes is a rail that did not answer.
      # The boundary scrub should make this unreachable; a rail doing its own
      # decoding can still get here, and it must not take the turn with it.
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
    def memoized(rail, text, ctx, &)
      return yield unless cache

      key = rail.respond_to?(:cache_key) ? rail.cache_key(text, ctx) : nil
      return yield if key.nil?

      cache.fetch(ctx[:side], rail.name, key, &)
    end
  end
end
