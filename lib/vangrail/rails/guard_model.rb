# frozen_string_literal: true

require_relative '../chat'
require_relative '../parsers'
require_relative '../rail'

module Vangrail
  module Rails
    # A safety classifier as a rail: one chat call, the model's own template
    # does the framing, and the label it answers becomes the decision.
    #
    #   :llama_guard   "safe" | "unsafe\nS1,S10"
    #   :apriel_guard  "safe\nnon_adversarial" | "unsafe-O14,O12\nadversarial"
    #
    # Classifiers only ever pass or block. They cannot rewrite text, so this
    # rail never returns :modified; a redaction or policy rail does that.
    #
    # Needs a provider that actually hosts one. Where none exists, Rails::
    # SelfCheck puts a written policy in front of an instruct model instead,
    # which is the same job done differently rather than the same job skipped.
    class GuardModel < Rail
      PRESETS = %i[llama_guard apriel_guard].freeze

      # Chat-template switch that turns on an assessment before the verdict.
      # Gateways forward these to the serving engine's template, so a written
      # rationale costs tokens and latency and nothing else.
      REASONING_KWARGS = { 'chat_template_kwargs' => { 'reasoning_mode' => 'on' } }.freeze
      REASONING_MAX_TOKENS = 900

      attr_reader :model, :preset, :chat, :reasoning

      def initialize(provider: nil, model: nil, preset: nil, chat: nil, reasoning: false,
                     name: nil, sides: Rail::SIDES, max_tokens: nil, **chat_options)
        @model = model || provider&.model(:guard)
        @preset = (preset || provider&.guard_preset)&.to_sym
        raise ArgumentError, 'a guard rail needs a model' if @model.nil?
        unless PRESETS.include?(@preset)
          raise ArgumentError, "preset must be one of #{PRESETS.join(', ')}; " \
                               'a model answering a written policy belongs in Rails::SelfCheck'
        end

        @reasoning = reasoning && @preset == :apriel_guard
        super(name: name || @preset.to_s, sides: sides)
        @chat = chat || build_chat(provider, max_tokens, chat_options)
      end

      def offline?
        false
      end

      # The verdict depends on the text and, on the output side, on the user
      # turn sent with it.
      def cache_key(text, context)
        return text if context[:side] == :input

        "#{context[:user_input]} #{text}"
      end

      def decide(text, context)
        answer = chat.ask(messages_for(text, context))
        parsed = preset == :apriel_guard ? Parsers.apriel_guard(answer.text) : Parsers.llama_guard(answer.text)
        unless parsed[:decided]
          return Result.new(status: :passed, rail: name, certain: false, model: model,
                            latency_ms: answer.latency_ms, raw: answer.raw,
                            reason: "unparsed guard response: #{parsed[:reason]}")
        end

        return pass(model: model, latency_ms: answer.latency_ms, raw: answer.raw) unless parsed[:violated]

        block(reason: parsed[:reason], categories: parsed[:categories], model: model,
              latency_ms: answer.latency_ms, raw: answer.raw)
      end

      private

      def build_chat(provider, max_tokens, chat_options)
        raise ArgumentError, 'a guard rail needs a provider or a chat client' unless provider

        Chat.new(
          model: model, base_url: provider.base_url, api_key: provider.api_key,
          max_tokens: max_tokens || (reasoning ? REASONING_MAX_TOKENS : 128),
          extra: reasoning ? REASONING_KWARGS : {},
          **chat_options
        )
      end

      # Guard models read a conversation, so an assistant turn is sent with the
      # user turn that prompted it when the caller knows it.
      def messages_for(text, context)
        return [{ 'role' => 'user', 'content' => text.to_s }] if context[:side] != :output

        messages = []
        user = context[:user_input].to_s
        messages << { 'role' => 'user', 'content' => user } unless user.strip.empty?
        messages << { 'role' => 'assistant', 'content' => text.to_s }
        messages
      end
    end
  end
end
