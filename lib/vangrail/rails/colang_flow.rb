# frozen_string_literal: true

require_relative '../colang/interpreter'
require_relative '../rail'

module Vangrail
  module Rails
    # A Colang flow as a rail.
    #
    # This is what lets a configuration folder written for the Python toolkit
    # run here: `rails.input.flows: [self check input]` becomes one of these,
    # the flow executes in Ruby, and its `bot refuse to respond` / `stop`
    # becomes a blocked Result carrying the refusal text.
    #
    # Not memoizable by default. A flow can call any registered action, and this
    # class cannot know whether one of them reads the passages or the history.
    class ColangFlow < Rail
      attr_reader :flow_name, :interpreter

      def initialize(flow_name:, program:, actions:, name: nil, sides: Rail::SIDES)
        super(name: name || flow_name, sides: sides)
        @flow_name = flow_name
        @interpreter = Colang::Interpreter.new(program: program, actions: actions)
      end

      def cache_key(_text, _context)
        nil
      end

      def call(text, context)
        outcome = interpreter.run(flow_name, context.merge(text: text))
        case outcome.status
        when :blocked then block(content: outcome.content, reason: outcome.reason || flow_name)
        when :modified then modify(outcome.content, reason: outcome.reason || flow_name)
        else pass
        end
      end
    end
  end
end
