# frozen_string_literal: true

require_relative 'errors'
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
        result = check_context(text_of(document), **context.merge(document: document, index: index))
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

      rails.each do |rail|
        next unless rail.applies_to?(side)

        result = invoke(rail, current, ctx)
        return result.with_rail(rail.name) if result.blocked?

        if result.modified?
          current = result.content_or(current)
          modified_by = rail.name
        end
        uncertain ||= result unless result.certain?
      end

      finish(side, current, modified_by, uncertain)
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
      return Result.new(status: :blocked, rail: rail.name, certain: false, reason: reason) if on_error == :block

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
