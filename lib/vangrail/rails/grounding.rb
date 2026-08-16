# frozen_string_literal: true

require_relative '../chat'
require_relative '../parsers'
require_relative '../policies'
require_relative '../rail'

module Vangrail
  module Rails
    # Does the answer say only what its passages support.
    #
    # Safety classifiers score hazards. For a retrieval system the failure that
    # matters is different and they cannot see it: an invented partition name, a
    # quota that appears nowhere, a citation pointing at a passage that does not
    # support the sentence in front of it. Those read exactly like real answers
    # to the person asking, which is the whole problem.
    #
    # Output side only, and never memoized: the verdict depends on the passage
    # set as well as the draft, so a changed retrieval must be judged again.
    class Grounding < Rail
      attr_reader :model, :chat, :policy

      def initialize(provider: nil, model: nil, chat: nil, policy: nil,
                     name: 'grounding', max_tokens: 256, **chat_options)
        super(name: name, sides: [:output])
        @model = model || provider&.model(:judge)
        @policy = policy || Policies.grounding_policy
        @chat = chat || begin
          raise ArgumentError, 'a grounding rail needs a provider or a chat client' unless provider

          Chat.new(model: @model, base_url: provider.base_url, api_key: provider.api_key,
                   max_tokens: max_tokens, **chat_options)
        end
      end

      def offline?
        false
      end

      # Not memoizable. Stated rather than left to a default so the reason is
      # visible where the decision is.
      def cache_key(_text, _context)
        nil
      end

      def decide(text, context)
        passages = Array(context[:passages])
        return unchecked('no passages supplied') if passages.empty?

        answer = chat.ask([
                            { 'role' => 'system', 'content' => policy },
                            { 'role' => 'user', 'content' => Policies.grounding_prompt(text, passages) },
                          ])
        parsed = Parsers.policy(answer.text)
        unless parsed[:decided]
          return unchecked("unparsed judge response: #{parsed[:reason]}",
                           model: model, latency_ms: answer.latency_ms, raw: answer.raw)
        end

        return pass(model: model, latency_ms: answer.latency_ms, raw: answer.raw) unless parsed[:violated]

        block(reason: parsed[:reason], categories: parsed[:categories], model: model,
              latency_ms: answer.latency_ms, raw: answer.raw)
      end
    end
  end
end
