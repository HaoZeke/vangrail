# frozen_string_literal: true

require_relative 'result'

module Vangrail
  # The whole rail protocol: a name, the sides it applies to, and `call`.
  #
  #   class ShoutRail < Vangrail::Rail
  #     def call(text, _context)
  #       return pass if text == text.downcase
  #
  #       modify(text.downcase, reason: 'lowered')
  #     end
  #   end
  #
  # Deliberately not a DSL. A rail is an object with one method, so a Ruby
  # application can write one in five lines, test it without a network, and put
  # it in the same ordered list as the model-backed ones.
  class Rail
    SIDES = %i[input output].freeze

    attr_reader :name, :sides

    def initialize(name: nil, sides: SIDES)
      @name = (name || default_name).to_s
      @sides = Array(sides).map(&:to_sym)
      unknown = @sides - SIDES
      raise ArgumentError, "unknown side(s): #{unknown.join(', ')}" unless unknown.empty?
    end

    def applies_to?(side)
      sides.include?(side.to_sym)
    end

    # Returns a Result. `context` is a hash the engine threads through:
    # :side, :user_input, :passages, :history, plus anything a caller adds.
    def call(_text, _context)
      raise NotImplementedError, "#{self.class} must implement #call"
    end

    # Does this rail need the network. Used to report a posture and to let a
    # caller build a model-free engine on purpose.
    def offline?
      false
    end

    def to_s
      name
    end

    private

    def pass(**kwargs)
      Result.passed(rail: name, **kwargs)
    end

    def modify(content, **kwargs)
      Result.modified(rail: name, content: content, **kwargs)
    end

    def block(**kwargs)
      Result.blocked(rail: name, **kwargs)
    end

    # A rail that could not reach a decision allows the text and says so. It
    # must never look like a clean check.
    def unchecked(reason)
      Result.unchecked(rail: name, reason: reason)
    end

    def default_name
      self.class.name.to_s.split('::').last
                    .gsub(/([a-z\d])([A-Z])/, '\1_\2').downcase
    end
  end
end
