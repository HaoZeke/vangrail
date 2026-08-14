# frozen_string_literal: true

require_relative '../chat'
require_relative '../parsers'
require_relative '../policies'
require_relative '../prompt'
require_relative '../rail'

module Vangrail
  # Rails that judge text against a written policy.
  module Rails
    # Puts a policy in the system message and the text in the user message, the
    # shape the policy-model guides describe. Any instruct model can serve; a
    # classifier cannot, because it answers with its own label tokens whatever
    # it is asked.
    #
    # This is the rail that a NeMo `self check input` or `self check output`
    # flow resolves to, so a config folder written for the Python toolkit runs
    # here unchanged.
    class SelfCheck < Rail
      attr_reader :model, :chat, :policy

      def initialize(provider: nil, policy: nil, model: nil, chat: nil,
                     name: 'self_check', sides: [:input], max_tokens: 256, **chat_options)
        super(name: name, sides: sides)
        @model = model || provider&.model(:judge)
        @policy = policy || default_policy(sides)
        raise ArgumentError, 'a self-check rail needs a model' if @model.nil? && chat.nil?

        @chat = chat || begin
          raise ArgumentError, 'a self-check rail needs a provider or a chat client' unless provider

          Chat.new(model: @model, base_url: provider.base_url, api_key: provider.api_key,
                   max_tokens: max_tokens, **chat_options)
        end
      end

      def cache_key(text, context)
        return text if context[:side] == :input

        "#{context[:user_input]} #{text}"
      end

      def call(text, context)
        rendered = Prompt.render(policy, template_context(text, context))
        answer = chat.ask([
                            { 'role' => 'system', 'content' => rendered },
                            { 'role' => 'user', 'content' => text.to_s }
                          ])
        parsed = Parsers.policy(answer.text)
        unless parsed[:decided]
          return Result.new(status: :passed, rail: name, certain: false, model: model,
                            latency_ms: answer.latency_ms, raw: answer.raw,
                            reason: "unparsed judge response: #{parsed[:reason]}")
        end

        return pass(model: model, latency_ms: answer.latency_ms, raw: answer.raw) unless parsed[:violated]

        block(reason: parsed[:reason], categories: parsed[:categories], model: model,
              latency_ms: answer.latency_ms, raw: answer.raw)
      end

      private

      # NeMo prompts address the text through `{{ user_input }}` or
      # `{{ bot_response }}`, so a policy carried over from a config folder
      # renders with the same names.
      def template_context(text, context)
        {
          'user_input' => (context[:side] == :input ? text : context[:user_input]).to_s,
          'bot_response' => (context[:side] == :output ? text : '').to_s,
          'context' => context
        }
      end

      def default_policy(sides)
        Array(sides).include?(:output) ? Policies.output_policy : Policies.input_policy
      end
    end
  end
end
