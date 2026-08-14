# frozen_string_literal: true

require_relative '../rail'

module NemoGuardrails
  module Rails
    # Blocks text matching any of a list of patterns.
    #
    # A guardrail stack that is only a language model has no floor: when the
    # endpoint is slow, cold, or down, every check degrades at once. A pattern
    # rail decides in microseconds, offline, and identically every time, so the
    # cases you can state exactly stay covered no matter what the network does.
    #
    #   Pattern.new(patterns: { 'instruction_override' => /ignore (all )?previous instructions/i })
    class Pattern < Rail
      attr_reader :patterns

      def initialize(patterns:, name: 'pattern', sides: Rail::SIDES, reason: nil)
        super(name: name, sides: sides)
        @patterns = normalize(patterns)
        @reason = reason
      end

      def offline?
        true
      end

      def cache_key(text, _context)
        text
      end

      def call(text, _context)
        hit = patterns.find { |_label, pattern| pattern.match?(text.to_s) }
        return pass unless hit

        label = hit.first
        block(categories: [label], reason: @reason || "matched #{label}")
      end

      private

      def normalize(patterns)
        case patterns
        when Hash then patterns.to_h { |k, v| [k.to_s, to_regexp(v)] }
        when Array then patterns.each_with_index.to_h { |v, i| ["pattern_#{i + 1}", to_regexp(v)] }
        else { 'pattern_1' => to_regexp(patterns) }
        end
      end

      def to_regexp(value)
        return value if value.is_a?(Regexp)

        Regexp.new(Regexp.escape(value.to_s), Regexp::IGNORECASE)
      end
    end
  end
end
