# frozen_string_literal: true

require_relative 'errors'
require_relative 'http'

module Vangrail
  # The other OpenAI-compatible endpoint: /completions, asked to score text
  # rather than to write any.
  #
  # It exists for one job. A chat endpoint returns what a model would say next
  # and never says how surprising the text it was given was, and that number is
  # what the published perplexity detectors are built on. The legacy completions
  # endpoint answers it directly: echo the prompt, generate nothing, and return
  # the log probability the model assigned each token of it.
  #
  # Support is genuinely uneven. Local servers built on llama.cpp and vLLM
  # answer it; several hosted APIs removed the endpoint, and a proxy in front of
  # a chat-only model cannot synthesise it. So `supported?` is a question worth
  # asking rather than an assumption, and everything here raises ProtocolError
  # rather than inventing a score when the fields are missing. A rail reading
  # this turns that into an uncertain result, which is the truth: the check did
  # not run.
  class Completion
    PATH = '/completions'

    attr_reader :model, :http

    def initialize(model:, http: nil, base_url: nil, api_key: nil,
                   open_timeout: HTTP::DEFAULT_OPEN_TIMEOUT,
                   read_timeout: HTTP::DEFAULT_READ_TIMEOUT)
      @model = model
      @http = HTTP.build(http: http, base_url: base_url, api_key: api_key,
                         open_timeout: open_timeout, read_timeout: read_timeout,
                         missing: 'a Completion needs a base_url or an http client')
    end

    # The log probability of each token of `text`, under this model.
    #
    # The first token has none, by construction: nothing preceded it. It is
    # dropped rather than counted as zero, because zero is a log probability of
    # one and would report the opening word as perfectly predicted.
    def token_logprobs(text)
      body = http.post_json(PATH, {
                              'model' => model,
                              'prompt' => text.to_s,
                              'max_tokens' => 0,
                              'echo' => true,
                              'logprobs' => 0,
                              'temperature' => 0,
                            })
      values = logprobs_in(body)
      raise ProtocolError, 'completions endpoint returned no token logprobs' if values.empty?

      values.compact
    end

    # Whether this endpoint can score at all. ProtocolError and HTTP 404 mean
    # it cannot; TransportError means it is down, which is a different
    # question. Asked once and kept, so a rail does not spend a scoring
    # request on a boolean every check.
    def supported?
      return @supported unless @supported.nil?

      @supported = token_logprobs('the quick brown fox').size > 1
    rescue ProtocolError
      @supported = false
    rescue HTTPError => e
      raise unless e.status == 404

      @supported = false
    end

    private

    def logprobs_in(body)
      choices = body.is_a?(Hash) ? body['choices'] : nil
      logprobs = choices.is_a?(Array) ? choices.dig(0, 'logprobs') : nil
      raise ProtocolError, 'completions endpoint returned no logprobs field' unless logprobs.is_a?(Hash)

      values = logprobs['token_logprobs']
      raise ProtocolError, 'completions endpoint returned no token_logprobs array' unless values.is_a?(Array)

      values.map { |value| value&.to_f }
    end
  end
end
