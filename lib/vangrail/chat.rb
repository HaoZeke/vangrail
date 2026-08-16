# frozen_string_literal: true

require_relative 'errors'
require_relative 'http'

module Vangrail
  # One OpenAI-compatible chat call, shared by every model-backed rail.
  #
  # Rails care about the text a model returned and how long it took. Everything
  # else about the protocol lives here, so a rail is a prompt and a parser.
  #
  # No endpoint is assumed. A Chat is built from a Provider, or from a base URL
  # given outright; there is no vendor to fall back to, because a guardrail that
  # quietly picks its own endpoint is one nobody can audit.
  class Chat
    COMPLETIONS_PATH = '/chat/completions'

    Answer = Struct.new(:text, :latency_ms, :raw, keyword_init: true)

    attr_reader :model, :http, :max_tokens, :temperature, :extra

    def initialize(model:, http: nil, base_url: nil, api_key: nil, max_tokens: 128,
                   temperature: 0, extra: {})
      @model = model
      @max_tokens = max_tokens
      @temperature = temperature
      @extra = extra
      @http = HTTP.build(http: http, base_url: base_url, api_key: api_key,
                         missing: 'a Chat needs a base_url or an http client')
    end

    # A copy pointed at a different model on the same endpoint and credentials.
    def with(model:, max_tokens: nil, extra: {})
      self.class.new(
        model: model, http: http, temperature: temperature,
        max_tokens: max_tokens || @max_tokens, extra: extra
      )
    end

    # `conversation:` is the application path: the messages are whatever
    # Conversation#messages will assemble, so a retrieved page cannot be
    # spliced into the instruction by handing this method a raw array.
    def ask(messages = nil, conversation: nil, system: nil, max_tokens: nil)
      if conversation
        raise ArgumentError, 'pass conversation: or messages, not both' if messages

        messages = conversation.messages(system: system.to_s)
      end
      raise ArgumentError, 'ask needs messages or conversation:' if messages.nil?

      payload = {
        'model' => model,
        'messages' => normalize(messages),
        'temperature' => temperature,
        'max_tokens' => max_tokens || @max_tokens,
        'stream' => false,
      }.merge(extra)

      t0 = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      body = http.post_json(COMPLETIONS_PATH, payload)
      ms = ((Process.clock_gettime(Process::CLOCK_MONOTONIC) - t0) * 1000).round
      Answer.new(text: content_of(body), latency_ms: ms, raw: body)
    end

    private

    def normalize(messages)
      Array(messages).map do |m|
        if m.is_a?(Hash)
          { 'role' => (m['role'] || m[:role]).to_s, 'content' => (m['content'] || m[:content]).to_s }
        else
          { 'role' => 'user', 'content' => m.to_s }
        end
      end
    end

    def content_of(body)
      choices = body.is_a?(Hash) ? body['choices'] : nil
      msg = choices.is_a?(Array) ? choices.dig(0, 'message') : nil
      return '' unless msg.is_a?(Hash)

      text = msg['content'].to_s
      # Reasoning models spend the budget on `reasoning` and can return a null
      # content. Read that rather than reading nothing.
      text.strip.empty? ? msg['reasoning'].to_s : text
    end
  end
end
