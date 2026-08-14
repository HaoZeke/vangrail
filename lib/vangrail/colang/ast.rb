# frozen_string_literal: true

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
          user_messages: user_messages.merge(other.user_messages)
        )
      end
    end

    Flow = Struct.new(:name, :body, :subflow, keyword_init: true)

    # $var = execute action(key="value")
    Assign = Struct.new(:variable, :expression, keyword_init: true)

    # execute action(key="value")
    Execute = Struct.new(:action, :arguments, keyword_init: true)

    # bot <message name>
    Bot = Struct.new(:message, keyword_init: true)

    # stop
    Stop = Struct.new(:reason, keyword_init: true)

    If = Struct.new(:condition, :then_body, :else_body, keyword_init: true)

    # Conditions
    Var = Struct.new(:name, keyword_init: true)
    Not = Struct.new(:expression, keyword_init: true)
    Compare = Struct.new(:left, :operator, :right, keyword_init: true)
    Literal = Struct.new(:value, keyword_init: true)
  end
end
