# frozen_string_literal: true

require_relative '../errors'

module Vangrail
  module Colang
    # The whole grammar this gem executes, as data. Everything the parser can
    # produce is one of these, which is also the honest statement of what a
    # Colang file may contain here: anything else is refused at parse time
    # rather than skipped at run time.
    Program = Struct.new(:flows, :bot_messages, :user_messages, keyword_init: true) do
      def flow(name)
        flows[name.to_s]
      end

      def flow_names
        flows.keys
      end

      def bot_message(name)
        bot_messages[name.to_s]
      end

      def merge(other)
        Program.new(
          flows: flows.merge(other.flows),
          bot_messages: bot_messages.merge(other.bot_messages),
          user_messages: user_messages.merge(other.user_messages),
        )
      end

      # Every `bot <name>` in every flow has a `define bot`. Called after
      # parse/merge, not during parse, so a bot defined in another file is
      # visible once the programs are joined.
      def check!
        flows.each { |name, flow| check_body(flow.body, name) }
        self
      end

      def check_body(body, flow_name)
        Array(body).each do |node|
          case node
          when Bot
            next if bot_message(node.message)

            raise ColangError, "no `define bot #{node.message}` for flow #{flow_name.inspect}"
          when If
            check_body(node.then_body, flow_name)
            check_body(node.else_body, flow_name)
          end
        end
      end
    end

    Flow = Struct.new(:name, :body, :subflow, keyword_init: true)

    # $var = <value>
    Assign = Struct.new(:variable, :expression, keyword_init: true)

    # execute action(key="value")
    Execute = Struct.new(:action, :arguments, keyword_init: true)

    # bot <message name>
    Bot = Struct.new(:message, keyword_init: true)

    # stop
    Stop = Struct.new(:reason, keyword_init: true)

    If = Struct.new(:condition, :then_body, :else_body, keyword_init: true)

    # Values
    Var = Struct.new(:name, keyword_init: true)
    Not = Struct.new(:expression, keyword_init: true)
    Compare = Struct.new(:left, :operator, :right, keyword_init: true)
    Literal = Struct.new(:value, keyword_init: true)
  end
end
