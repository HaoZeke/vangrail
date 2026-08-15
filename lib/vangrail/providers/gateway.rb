# frozen_string_literal: true

require_relative '../provider'

module Vangrail
  module Providers
    # A shared OpenAI-compatible gateway, described by configuration rather than
    # compiled in.
    #
    # Institutions and vendors each run one, on their own hostname, with their
    # own credential source and their own model names. None of that is knowledge
    # a general-purpose gem should carry: a hostname in this source is an
    # endpoint every installation inherits whether it can reach it or not, and a
    # credential path is worse, because it says where somebody's secrets live.
    #
    # So a gateway is registered by the application that has one:
    #
    #   Vangrail::Providers.register_gateway(
    #     name: 'hub',
    #     base_url: 'https://gateway.example/api/v0',
    #     models: { judge: 'some/instruct-model', guard: 'some/guard-model' },
    #     guard_preset: :apriel_guard,
    #     key_env: 'HUB_API_KEY',
    #     key_file: File.join(Dir.home, '.config', 'hub', 'api_key'),
    #     pass_entry: 'hub/token'
    #   )
    #
    # or by environment, so a deployment needs no code at all:
    #
    #   GUARDRAILS_GATEWAY_NAME, _API_BASE, _API_KEY, _MODEL, _JUDGE_MODEL,
    #   _GUARD_PRESET, _KEY_FILE, _PASS_ENTRY
    #
    # Credentials resolve in one order, most explicit first: the environment
    # variable, then a key file, then `pass`. Nothing is cached across a
    # `reset!`, so a test can point the lookups at nothing and mean it.
    module Gateway
      ENV_PREFIX = 'GUARDRAILS_GATEWAY'

      # `key_env`, `file_env`, and `pass_env` name the environment variables
      # that override each source. They are named rather than derived: a
      # deployment that already documents WILLMA_PASS_ENTRY should not have to
      # rename it to match a convention this gem invented.
      Spec = Struct.new(:name, :base_url, :models, :guard_preset, :key_env, :file_env, :pass_env,
                        :key_file, :pass_entry, keyword_init: true)

      module_function

      # Builds a Provider from a Spec. The token is resolved lazily and memoized
      # per spec, so `pass` runs at most once per process.
      def provider(spec, env = ENV)
        tokens = {}
        Provider.new(
          name: spec.name,
          base_url: spec.base_url,
          models: spec.models || {},
          guard_preset: spec.guard_preset,
          key_resolver: lambda do
            tokens[spec.name] ||= token(spec, env)
          end,
        )
      end

      def token(spec, env = ENV)
        from_env(spec, env) || from_file(spec, env) || from_pass(spec, env)
      end

      def from_env(spec, env)
        return nil unless spec.key_env

        present(env[spec.key_env])
      end

      # The override replaces the configured path rather than being tried before
      # it. Pointing it at a file that does not exist has to mean "no key here":
      # otherwise there is no way to run without credentials on a machine that
      # happens to have some, which is exactly what a test needs to do.
      def from_file(spec, env)
        var = spec.file_env || (spec.key_env && "#{spec.key_env}_FILE")
        override = var && present(env[var])
        path = override || spec.key_file
        return nil unless path && File.file?(path)

        present(File.read(path).lines.first)
      end

      # stdin is closed for the child: gpg reads stdin, and a helper that
      # inherits a caller's stdin can consume input the caller still needs or
      # block forever on a pinentry prompt.
      def from_pass(spec, env = ENV)
        entry = (spec.pass_env && present(env[spec.pass_env])) || spec.pass_entry
        return nil unless entry

        out = IO.popen(['pass', 'show', entry], in: File::NULL, err: File::NULL, &:read)
        return nil unless $?&.success?

        present(out.to_s.lines.first)
      # A missing `pass`, a locked keyring, a refused pinentry: none of them are
      # this method's problem, and all of them mean the same thing here, which is
      # that no credential came from this source.
      rescue StandardError
        nil
      end

      # A gateway described entirely by environment, or nil when none is.
      def from_environment(env = ENV)
        base = present(env["#{ENV_PREFIX}_API_BASE"])
        return nil unless base

        Spec.new(
          name: present(env["#{ENV_PREFIX}_NAME"]) || 'gateway',
          base_url: base,
          models: {
            judge: present(env["#{ENV_PREFIX}_JUDGE_MODEL"]) || present(env["#{ENV_PREFIX}_MODEL"]),
            guard: present(env["#{ENV_PREFIX}_GUARD_MODEL"]),
          }.compact,
          guard_preset: present(env["#{ENV_PREFIX}_GUARD_PRESET"])&.to_sym,
          key_env: "#{ENV_PREFIX}_API_KEY",
          file_env: "#{ENV_PREFIX}_KEY_FILE",
          pass_env: "#{ENV_PREFIX}_PASS_ENTRY",
          key_file: present(env["#{ENV_PREFIX}_KEY_FILE"]),
          pass_entry: present(env["#{ENV_PREFIX}_PASS_ENTRY"]),
        )
      end

      def present(value)
        s = value.to_s.strip
        s.empty? ? nil : s
      end
    end
  end
end
