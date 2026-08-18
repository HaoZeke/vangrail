# frozen_string_literal: true

require_relative 'assessor'
require_relative 'errors'
require_relative 'rail'
require_relative 'result'
require_relative 'result_cache'
require_relative 'screening'

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
    Screening = Vangrail::Screening
    Triage = Vangrail::Triage

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

    def screen(...) = Screening.run(self, ...)

    def assess(...) = Assessor.new(self).assess(...)

    def triage(...) = Assessor.new(self).triage(...)

    def rails(side)
      case side.to_sym
      when :input then input_rails
      when :context then context_rails
      when :output then output_rails
      else raise ArgumentError, "unknown side: #{side}"
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

    # Public so Assessor can run one rail without going through #run.
    def invoke(rail, text, ctx)
      memoized(rail, text, ctx) { call_rail(rail, text, ctx) }
    end

    private

    def run(side, rails, text, context)
      return Result.unchecked(rail: side, reason: "no #{side} rails configured") if rails.empty?

      ctx = context.merge(side: side)
      current = Rail.usable(text)
      modified_by = nil
      rewrites = []
      rewrite_categories = []
      uncertain = nil
      unbuilt = nil

      rails.each do |rail|
        next unless rail.applies_to?(side)

        result = invoke(rail, current, ctx)
        if result.blocked?
          known = result.certain? && uncertain.nil? && unbuilt.nil?
          kept = modified_by ? current : result.content
          blocked = result.with_rail(rail.name, content: kept, certain: known)
          # A block after a rewrite is still a pass where text was changed, and
          # whoever reads the record needs both facts.
          return rewrites.empty? ? blocked : blocked.with_rewrites(rewrites)
        end

        if result.modified?
          current = result.content_or(current)
          modified_by = rail.name
          rewrites << rail.name
          rewrite_categories.concat(Array(result.categories))
        end
        next if result.certain?

        # A rail that ran and could not decide says more than a rail that was
        # never built, so its reason is the one the caller sees. Without this,
        # a placeholder earlier in the list reports "no endpoint was resolved"
        # over the rail that actually tried and had the connection refused.
        if rail.placeholder?
          unbuilt ||= result
        else
          uncertain ||= result
        end
      end

      finish(side, current, modified_by, uncertain || unbuilt,
             rewrites: rewrites, categories: rewrite_categories.uniq)
    end

    # The reported rail is the last one that rewrote the text, and the chain and
    # the categories are every rail that did. Reporting only the last one lost a
    # redaction behind a later disclosure mark: same status, same content, and an
    # audit record that no longer said a credential had been taken out.
    def finish(side, current, modified_by, uncertain, rewrites: [], categories: [])
      if modified_by
        return Result.modified(rail: modified_by, content: current,
                               certain: uncertain.nil?, reason: uncertain&.reason,
                               categories: categories, rewritten_by: rewrites)
      end
      return Result.unchecked(rail: uncertain.rail || side, reason: uncertain.reason) if uncertain

      Result.passed(rail: side)
    end

    def call_rail(rail, text, ctx)
      result = rail.call(text, ctx)
      return result if result.is_a?(Result)

      raise ProtocolError, "#{rail.name} returned #{result.class}, expected Vangrail::Result"
    rescue Error => e
      failed(rail, e)
    rescue ArgumentError, EncodingError => e
      # A rail that could not read the bytes is a rail that did not answer.
      # Rail#call scrubs first; a rail doing its own decoding can still get
      # here, and it must not take the turn with it.
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

      # Key the readable form. Raw bytes can carry a NUL or a wrong tag
      # and would store the same decision under two keys.
      key = rail.cache_key(Rail.usable(text), ctx)
      return yield if key.nil?

      cache.fetch(ctx[:side], rail.name, key, &)
    end
  end
end
