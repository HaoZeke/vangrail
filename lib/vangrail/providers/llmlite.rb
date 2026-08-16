# frozen_string_literal: true

require 'socket'
require_relative '../provider'

module Vangrail
  module Providers
    # llmlite: a local OpenAI-compatible proxy, and the default this gem builds
    # around.
    #
    # It is the right default for guardrails specifically. Rails run on every
    # turn, so their latency and their failure modes are the application's; a
    # local endpoint keeps both on this machine, needs no shared credential, and
    # cannot bill anyone. It also means a laptop with the proxy running, and a
    # model named, has working rails with no shared credential to configure.
    #
    # The proxy serves an instruct model, not a safety classifier, so
    # `model(:guard)` is nil and the builder puts a policy rail on the input
    # side. That is a real difference between endpoints, and it belongs here
    # rather than in a rail deciding what it is talking to.
    module Llmlite
      HOST = '127.0.0.1'
      DEFAULT_PORT = 8760
      LISTEN_ERRORS = [
        Errno::ECONNREFUSED, Errno::EHOSTUNREACH, Errno::ENETUNREACH,
        Errno::ECONNRESET, Errno::ETIMEDOUT, Errno::EADDRNOTAVAIL, SocketError
      ].freeze

      module_function

      def port(env = ENV)
        (env['LLMLITE_PORT'] || env['GROK_SHIM_PORT'] || DEFAULT_PORT).to_i
      end

      def host(env = ENV)
        env['LLMLITE_HOST'].to_s.strip.empty? ? HOST : env['LLMLITE_HOST'].strip
      end

      def base_url(env = ENV)
        "http://#{host(env)}:#{port(env)}/v1"
      end

      # A TCP connect, not a request: a proxy that is not running is the common
      # case, and finding that out must cost microseconds rather than a timeout.
      def listening?(env = ENV)
        socket = TCPSocket.new(host(env), port(env))
        socket.close
        true
      rescue *LISTEN_ERRORS
        false
      end

      def model(env = ENV)
        present(env['LLMLITE_MODEL'] || env['GROK_LLMLITE_MODEL'])
      end

      # No default. Which embedding model a proxy serves, if any, is deployment
      # knowledge, and a guessed name costs a 404 on every check while looking
      # like a rail that ran.
      def embed_model(env = ENV)
        present(env['LLMLITE_EMBED_MODEL'] || env['GUARDRAILS_EMBED_MODEL'])
      end

      def key(env = ENV)
        present(env['LLMLITE_API_KEY'])
      end

      def provider(env = ENV)
        resolved = key(env)
        Provider.new(
          name: 'llmlite',
          base_url: base_url(env),
          models: { judge: model(env), guard: nil, embed: embed_model(env) },
          key_resolver: resolved && -> { resolved },
          local: true,
          probe: -> { listening?(env) },
        )
      end

      def present(value)
        s = value.to_s.strip
        s.empty? ? nil : s
      end
    end
  end
end
