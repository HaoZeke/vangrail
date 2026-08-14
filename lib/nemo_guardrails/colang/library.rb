# frozen_string_literal: true

require_relative 'parser'

module NemoGuardrails
  module Colang
    # The flows a configuration can name without defining.
    #
    # A config folder that lists `self check input` under `rails.input.flows`
    # and ships no `.co` file is the ordinary case: those flows are built into
    # the toolkit. They are written out here as Colang rather than hand-built
    # AST, so the parser this gem ships is the same one that reads them, and a
    # bug in it fails loudly on the built-ins instead of hiding until someone
    # writes their own flow.
    module Library
      SOURCE = <<~COLANG
        define flow self check input
          $allowed = execute self_check_input
          if not $allowed
            bot refuse to respond
            stop

        define flow self check output
          $allowed = execute self_check_output
          if not $allowed
            bot refuse to respond
            stop

        define flow self check facts
          $accurate = execute self_check_facts
          if not $accurate
            bot inform answer unknown
            stop

        define bot refuse to respond
          "I'm sorry, I can't respond to that."

        define bot inform answer unknown
          "I don't know the answer to that."
      COLANG

      module_function

      def program
        @program ||= Parser.parse(SOURCE, filename: 'built-in')
      end

      def flow_names
        program.flow_names
      end
    end
  end
end
