# frozen_string_literal: true

require_relative '../rail'

module NemoGuardrails
  module Rails
    # Stands in for a rail that was asked for and could not be built.
    #
    # Without this, a configuration asking for a model-backed rail against an
    # endpoint that is down produces an engine holding only its offline rails.
    # Those rails pass, the engine reports passed and certain, and the answer is
    # a lie: the check the operator configured never ran.
    #
    # A placeholder that always returns unchecked keeps the arithmetic right.
    # The turn is allowed, the engine's result is uncertain, and the reason
    # names what is missing and why.
    class Missing < Rail
      attr_reader :reason

      def initialize(reason:, name: 'missing', sides: Rail::SIDES)
        super(name: name, sides: sides)
        @reason = reason
      end

      def offline?
        true
      end

      def call(_text, _context)
        unchecked(reason)
      end
    end
  end
end
