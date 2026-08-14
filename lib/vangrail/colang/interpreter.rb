# frozen_string_literal: true

require_relative '../errors'
require_relative 'ast'

module Vangrail
  module Colang
    # Runs one flow and reports what it decided.
    #
    # The mapping onto rail statuses is the whole design:
    #
    #   `bot <message>` then `stop`     -> blocked, with the message as content
    #   assignment to $user_message or
    #   $bot_message                    -> modified, with the new value
    #   falls off the end               -> passed
    #
    # A `stop` without a preceding `bot` still blocks; it just has no refusal
    # text to show. Actions are plain Ruby callables, so the flow decides the
    # control shape and Ruby does the work.
    class Interpreter
      # Variables a flow assigns to when it rewrites the turn rather than
      # refusing it, matching the names the toolkit's own flows use.
      CONTENT_VARS = %w[user_message bot_message user_input bot_response].freeze

      Outcome = Struct.new(:status, :content, :reason, :variables, keyword_init: true)

      # Raised through the interpreter to unwind a flow on `stop`.
      class Stopped < StandardError
        attr_reader :message_text

        def initialize(message_text)
          @message_text = message_text
          super('flow stopped')
        end
      end

      attr_reader :program, :actions

      def initialize(program:, actions:)
        @program = program
        @actions = actions
      end

      def run(flow_name, context = {})
        flow = program.flow(flow_name)
        raise UnknownAction, "no flow named #{flow_name.inspect}" unless flow

        state = { 'context' => context }
        last_bot = nil
        begin
          last_bot = execute(flow.body, state, context)
        rescue Stopped => e
          return Outcome.new(status: :blocked, content: e.message_text, reason: flow_name, variables: state)
        end

        rewrite = CONTENT_VARS.filter_map { |v| state[v] if state.key?(v) }.last
        return Outcome.new(status: :modified, content: rewrite.to_s, reason: flow_name, variables: state) if rewrite

        Outcome.new(status: :passed, content: last_bot, reason: nil, variables: state)
      end

      private

      # Returns the text of the last `bot` statement reached, so a flow that
      # says something without stopping still hands that text back.
      def execute(body, state, context)
        said = nil
        body.each do |node|
          case node
          when Assign then state[node.variable] = evaluate(node.expression, state, context)
          when Execute then evaluate(node, state, context)
          when Bot then said = bot_text(node.message)
          when Stop then raise Stopped, said
          when If then said = branch(node, state, context) || said
          else raise ColangError, "cannot execute #{node.class}"
          end
        end
        said
      end

      def branch(node, state, context)
        taken = truthy?(evaluate(node.condition, state, context)) ? node.then_body : node.else_body
        execute(Array(taken), state, context)
      end

      def evaluate(node, state, context)
        case node
        when Execute then call_action(node, state, context)
        when Var then state[node.name]
        when Literal then node.value
        when Not then !truthy?(evaluate(node.expression, state, context))
        when Compare then compare(node, state, context)
        else node
        end
      end

      def compare(node, state, context)
        left = evaluate(node.left, state, context)
        right = evaluate(node.right, state, context)
        node.operator == '==' ? left == right : left != right
      end

      def call_action(node, state, context)
        action = actions[node.action]
        raise UnknownAction, "no action registered for #{node.action.inspect}" unless action

        args = node.arguments.transform_values { |v| v.is_a?(Var) ? state[v.name] : v }
        action.call(args, context)
      end

      def bot_text(message)
        alternatives = program.bot_message(message)
        raise UnknownAction, "no `define bot #{message}` for this flow" unless alternatives

        # Deterministic: a guardrail refusal that varies between runs makes an
        # incident report harder to read for no benefit.
        alternatives.first
      end

      def truthy?(value)
        return false if value.nil? || value == false
        return false if value.respond_to?(:empty?) && value.empty?

        true
      end
    end
  end
end
