# frozen_string_literal: true

require_relative '../provider'

module NemoGuardrails
  module Providers
    # A shared OpenAI-compatible gateway that also hosts safety classifiers.
    #
    # Registered second, behind llmlite: a local endpoint costs nothing and
    # answers on the loopback, so it wins when it is up. What this one adds is
    # `model(:guard)`, a dedicated classifier, which turns the input rail from a
    # policy prompt into a purpose-built model.
    #
    # Latency mode decides the default. A classifier that cold-starts on first
    # call cannot sit in a request path, so the always-loaded one is picked even
    # though it is not the largest.
    module Willma
      BASE_URL = 'https://willma.surf.nl/api/v0'
      KEY_FILE = File.join(Dir.home, '.config', 'surf-ai-hub', 'api_key')
      PASS_ENTRY = 'surf/ai-hub/token'

      GUARD_MODELS = {
        'ServiceNow-AI/AprielGuard' => { preset: :apriel_guard, always_on: true },
        'meta-llama/Llama-Guard-3-8B' => { preset: :llama_guard, always_on: false }
      }.freeze

      DEFAULT_GUARD_MODEL = 'ServiceNow-AI/AprielGuard'
      DEFAULT_JUDGE_MODEL = 'mistralai/Mistral-Small-3.2-24B-Instruct-2506'

      module_function

      def base_url(env = ENV)
        value = env['WILLMA_API_BASE'].to_s.strip
        value.empty? ? BASE_URL : value.sub(%r{/+\z}, '')
      end

      def preset_for(model)
        GUARD_MODELS.dig(model.to_s, :preset)
      end

      def always_on?(model)
        GUARD_MODELS.dig(model.to_s, :always_on) == true
      end

      # First source that resolves, or nil. Cached per process so `pass` runs
      # once. stdin is closed for the child: gpg reads stdin, and a helper that
      # inherits a caller's stdin can eat input the caller still needs or block
      # forever on a pinentry prompt.
      def token(env = ENV)
        return @token if defined?(@token)

        @token = present(env['WILLMA_API_KEY']) || token_from_file(env) || token_from_pass(env)
      end

      def reset!
        remove_instance_variable(:@token) if defined?(@token)
      end

      def token_from_file(env = ENV)
        path = env['WILLMA_API_KEY_FILE'].to_s.strip
        path = KEY_FILE if path.empty?
        return nil unless File.file?(path)

        present(File.read(path).lines.first)
      end

      def token_from_pass(env = ENV)
        entry = env['WILLMA_PASS_ENTRY'].to_s.strip
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

      def provider(env = ENV)
        guard = present(env['GUARDRAILS_MODEL']) || DEFAULT_GUARD_MODEL
        Provider.new(
          name: 'willma',
          base_url: base_url(env),
          models: { judge: present(env['GUARDRAILS_JUDGE_MODEL']) || DEFAULT_JUDGE_MODEL, guard: guard },
          key_resolver: -> { token(env) },
          guard_preset: preset_for(guard) || :apriel_guard
        )
      end
    end
  end
end
