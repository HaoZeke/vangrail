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
    #   a change to a content binding   -> modified, with the new value
    #   falls off the end               -> passed
    #
    # `$user_input` is a rewrite alias of `$user_message`; `$bot_response` is
    # a rewrite alias of `$bot_message`. Input and context seed the user pair
    # from the turn text; output seeds the bot pair. The other pair is left
    # unset so an output flow that reads `$user_message` is not reading the
    # answer unless the caller put it there.
    #
    # A `stop` without a preceding `bot` still blocks; it just has no refusal
    # text to show. Actions are plain Ruby callables, so the flow decides the
    # control shape and Ruby does the work.
    class Interpreter
      # The four names a flow assigns to when it rewrites the turn. Order is
      # the last-write winner when more than one of them changed.
      CONTENT_VARS = %w[user_message bot_message user_input bot_response].freeze

      Outcome = Struct.new(:status, :content, :reason, :variables, keyword_init: true)

      attr_reader :program, :actions

      def initialize(program:, actions:)
        @program = program.check!
        @actions = actions
      end

      def run(flow_name, context = {})
        flow = program.flow(flow_name)
        raise ColangError, "no flow named #{flow_name.inspect}" unless flow

        seeds = seed_bindings(context)
        state = { 'context' => context }.merge(seeds)
        result = execute(flow.body, state, context)
        return stop_outcome(result.last, flow_name, state) if stop_tag?(result)

        rewrite = rewritten_content(state, seeds)
        if rewrite
          return Outcome.new(status: :modified, content: rewrite.to_s, reason: flow_name,
                             variables: state)
        end

        Outcome.new(status: :passed, content: result, reason: nil, variables: state)
      end

      private

      # Returns the text of the last `bot` statement reached, so a flow that
      # says something without stopping still hands that text back. `stop`
      # returns `[:stop, said]` rather than raising.
      def execute(body, state, context)
        said = nil
        body.each do |node|
          case node
          when Assign then state[node.variable] = evaluate(node.expression, state, context)
          when Execute then evaluate(node, state, context)
          when Bot then said = bot_text(node.message)
          when Stop then return [:stop, said]
          when If
            result = branch(node, state, context)
            return result if stop_tag?(result)

            said = result || said
          else raise ColangError, "cannot execute #{node.class}"
          end
        end
        said
      end

      def stop_tag?(result)
        result.is_a?(Array) && result.first == :stop
      end

      def stop_outcome(content, flow_name, state)
        Outcome.new(status: :blocked, content: content, reason: flow_name, variables: state)
      end

      def seed_bindings(context)
        text = context[:text]
        if context[:side] == :output
          { 'bot_message' => text, 'bot_response' => text }
        else
          { 'user_message' => text, 'user_input' => text }
        end
      end

      def rewritten_content(state, seeds)
        rewritten = CONTENT_VARS.filter_map do |name|
          next unless state.key?(name)
          next if seeds.key?(name) && state[name] == seeds[name]

          state[name]
        end
        rewritten.last
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

        args = node.arguments.transform_values { |v| evaluate(v, state, context) }
        action.call(args, context)
      end

      def bot_text(message)
        alternatives = program.bot_message(message)
        raise ColangError, "no `define bot #{message}` for this flow" unless alternatives

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
