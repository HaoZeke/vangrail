# frozen_string_literal: true

require_relative 'errors'

module NemoGuardrails
  # SURF AI Hub (Willma), the OpenAI-compatible gateway this gem targets by
  # default: https://willma.surf.nl/api/v0 with `Authorization: Bearer <token>`.
  #
  # The hub hosts the guard models a rail needs, so a Ruby application can run
  # input and output rails without standing up a Python service. Tokens never
  # live in source: they resolve from the environment, a key file, or `pass`.
  module Willma
    module_function

    BASE_URL = 'https://willma.surf.nl/api/v0'
    KEY_FILE = File.join(Dir.home, '.config', 'surf-ai-hub', 'api_key')
    PASS_ENTRY = 'surf/ai-hub/token'

    # Guard models on the hub. `always_on` models answer immediately; the rest
    # cold-start on first call, which a rail in a request path cannot absorb.
    GUARD_MODELS = {
      'ServiceNow-AI/AprielGuard' => { preset: :apriel_guard, always_on: true },
      'meta-llama/Llama-Guard-3-8B' => { preset: :llama_guard, always_on: false },
      'openai/gpt-oss-safeguard-120b' => { preset: :policy, always_on: false }
    }.freeze

    # AprielGuard is the always-on choice, so a rail built on it adds one
    # round trip rather than a model load.
    DEFAULT_GUARD_MODEL = 'ServiceNow-AI/AprielGuard'

    # Instruct model for a policy rail on a host without a dedicated guard model.
    FALLBACK_JUDGE_MODEL = 'mistralai/Mistral-Small-3.2-24B-Instruct-2506'

    def base_url
      env = ENV['WILLMA_API_BASE'].to_s.strip
      env.empty? ? BASE_URL : env.sub(%r{/+\z}, '')
    end

    def guard_model
      env = ENV['GUARDRAILS_MODEL'].to_s.strip
      env.empty? ? DEFAULT_GUARD_MODEL : env
    end

    def preset_for(model)
      entry = GUARD_MODELS[model.to_s]
      return entry[:preset] if entry

      # An unlisted model still works as a policy judge: the policy prompt asks
      # for a verdict any instruct model can produce.
      :policy
    end

    def always_on?(model)
      GUARD_MODELS.dig(model.to_s, :always_on) == true
    end

    # First token that resolves, or nil. Cached so `pass` runs once per process.
    def token
      return @token if defined?(@token)

      @token = token_from_env || token_from_file || token_from_pass
    end

    def token!
      token || raise(MissingToken, 'no SURF AI Hub token in WILLMA_API_KEY, ' \
                                   "#{KEY_FILE}, or `pass show #{PASS_ENTRY}`")
    end

    def reset!
      remove_instance_variable(:@token) if defined?(@token)
    end

    def available?
      !token.nil?
    end

    def token_from_env
      present(ENV['WILLMA_API_KEY']) || present(ENV['GUARDRAILS_API_KEY'])
    end

    def token_from_file
      path = ENV['WILLMA_API_KEY_FILE'].to_s.strip
      path = KEY_FILE if path.empty?
      return nil unless File.file?(path)

      present(File.read(path).lines.first)
    end

    # stdin is closed for the child: `pass` shells out to gpg, and gpg reads
    # stdin. A helper that inherits a caller's stdin can consume input the
    # caller still needs, or block forever on a pinentry prompt.
    def token_from_pass
      entry = ENV['WILLMA_PASS_ENTRY'].to_s.strip
      entry = PASS_ENTRY if entry.empty?
      out = IO.popen(['pass', 'show', entry], in: File::NULL, err: File::NULL, &:read)
      return nil unless $?&.success?

      present(out.to_s.lines.first)
    rescue Errno::ENOENT, StandardError
      nil
    end

    def present(value)
      s = value.to_s.strip
      s.empty? ? nil : s
    end
  end
end
