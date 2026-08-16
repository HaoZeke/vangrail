# frozen_string_literal: true

module Vangrail
  class Client
    # A guardrailed chat turn, read out of either server response shape.
    #
    # The OpenAI-compatible shape puts the answer in choices[0].message.content
    # and rail bookkeeping under a top-level `guardrails` object. The older shape
    # answers with a bare {role, content} message (or a list of them) and puts
    # bookkeeping at the top level. Both appear in the wild depending on the
    # server version, so this reads whichever is present.
    class Turn
      # Server-side names for the variables holding the rail that stopped a turn.
      INPUT_RAIL_VAR = 'triggered_input_rail'
      OUTPUT_RAIL_VAR = 'triggered_output_rail'

      attr_reader :raw

      def initialize(raw)
        @raw = raw.is_a?(Hash) ? raw : {}
      end

      def content
        choice = choices.first
        if choice.is_a?(Hash)
          msg = choice['message'] || choice['delta'] || {}
          return msg['content'].to_s if msg.is_a?(Hash) && msg.key?('content')
        end
        return raw['content'].to_s if raw.key?('content')

        messages = raw['messages']
        if messages.is_a?(Array)
          last = messages.reverse.detect { |m| m.is_a?(Hash) && m['role'].to_s == 'assistant' }
          return last['content'].to_s if last
        end
        ''
      end

      def config_id
        guardrails['config_id']
      end

      # The rail that stopped this turn, or nil. Reported only when the request
      # asked for the output variables that carry it.
      def triggered_input_rail
        output_data[INPUT_RAIL_VAR]
      end

      def triggered_output_rail
        output_data[OUTPUT_RAIL_VAR]
      end

      def triggered_rail
        triggered_input_rail || triggered_output_rail
      end

      # Rails that ran, from options.log.activated_rails. Empty unless logging
      # was requested; an empty list is not evidence that no rail ran.
      def activated_rails
        entries = log['activated_rails']
        entries.is_a?(Array) ? entries : []
      end

      def stopped_rails
        activated_rails.select { |r| r.is_a?(Hash) && r['stop'] == true }
      end

      # True when a rail is known to have stopped the turn. Absent explicit
      # signals this stays false, so a refusal the model wrote itself is never
      # reported as a rail decision.
      def blocked?
        return true unless triggered_rail.nil?

        !stopped_rails.empty?
      end

      def allowed?
        !blocked?
      end

      def model
        raw['model']
      end

      def guardrails
        g = raw['guardrails']
        g.is_a?(Hash) ? g : {}
      end

      def output_data
        d = guardrails['output_data'] || raw['output_data']
        d.is_a?(Hash) ? d : {}
      end

      def log
        l = guardrails['log'] || raw['log']
        l.is_a?(Hash) ? l : {}
      end

      def llm_calls
        calls = log['llm_calls']
        calls.is_a?(Array) ? calls : []
      end

      # Total tokens the rails plus the answer spent, when the server reports it.
      def total_tokens
        usage = raw['usage']
        return usage['total_tokens'] if usage.is_a?(Hash) && usage['total_tokens']

        sums = llm_calls.filter_map { |c| c['total_tokens'] if c.is_a?(Hash) }
        sums.empty? ? nil : sums.sum
      end

      private

      def choices
        c = raw['choices']
        c.is_a?(Array) ? c : []
      end
    end
  end
end
