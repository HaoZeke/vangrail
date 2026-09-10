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
    #   :harmful_yes_no  "Harmful request: yes" | "Yes", the WildGuard and
    #                    ShieldGemma shape, where the polarity belongs to the
    #                    question the model was trained on rather than to the token
    #   :three_label     "safe" | "unsafe" | "controversial", the Qwen Guard shape
    #
    # There are at least six of these formats in current use across fourteen
    # published guard models (Sadeghi et al., arXiv:2605.28830), and a format
    # this gem cannot read makes every check unchecked rather than wrong. That
    # is the safe failure and it is still a rail that does nothing, which is why
    # the list is longer than the two it started with.
    #
    # Classifiers only ever pass or block. They cannot rewrite text, so this
    # rail never returns :modified; a redaction or policy rail does that.
    #
    # Needs a provider that actually hosts one. Where none exists, Rails::
    # SelfCheck puts a written policy in front of an instruct model instead,
    # which is the same job done differently rather than the same job skipped.
    class GuardModel < Rail
      PRESETS = %i[llama_guard apriel_guard harmful_yes_no three_label].freeze

      # What a third label means, where a model has one. Counted as unsafe
      # because the alternative is measurably worse: dropping "controversial"
      # cost one model 37.2 points of recall in the benchmark above. :safe and
      # :undecided are available for a deployment that has decided otherwise,
      # and neither is the default.
      MIDDLE_LABELS = %i[unsafe safe undecided].freeze

      # Chat-template switch that turns on an assessment before the verdict.
      # Gateways forward these to the serving engine's template, so a written
      # rationale costs tokens and latency and nothing else.
      REASONING_KWARGS = { 'chat_template_kwargs' => { 'reasoning_mode' => 'on' } }.freeze
      REASONING_MAX_TOKENS = 900

      attr_reader :model, :preset, :chat, :reasoning, :middle

      def initialize(provider: nil, model: nil, preset: nil, chat: nil, reasoning: false,
                     middle: :unsafe, name: nil, sides: Rail::SIDES, max_tokens: nil, **chat_options)
        @model = model || provider&.model(:guard)
        @preset = (preset || provider&.guard_preset)&.to_sym
        raise ArgumentError, 'a guard rail needs a model' if @model.nil?
        unless PRESETS.include?(@preset)
          raise ArgumentError, "preset must be one of #{PRESETS.join(', ')}; " \
                               'a model answering a written policy belongs in Rails::SelfCheck'
        end

        @middle = middle.to_sym
        unless MIDDLE_LABELS.include?(@middle)
          raise ArgumentError, "middle must be one of #{MIDDLE_LABELS.join(', ')}"
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
        parsed = parse(answer.text)
        unless parsed[:decided]
          return unchecked("unparsed guard response: #{parsed[:reason]}",
                           model: model, latency_ms: answer.latency_ms, raw: answer.raw)
        end

        return pass(model: model, latency_ms: answer.latency_ms, raw: answer.raw) unless parsed[:violated]

        block(reason: parsed[:reason], categories: parsed[:categories], model: model,
              latency_ms: answer.latency_ms, raw: answer.raw)
      end

      private

      def parse(body)
        case preset
        when :apriel_guard then Parsers.apriel_guard(body)
        when :harmful_yes_no then Parsers.harmful_yes_no(body)
        when :three_label then Parsers.three_label_guard(body, middle: middle)
        else Parsers.llama_guard(body)
        end
      end

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
