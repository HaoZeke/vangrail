# frozen_string_literal: true

require_relative 'provider'
require_relative 'providers/llmlite'
require_relative 'providers/willma'

module NemoGuardrails
  # Endpoint presets, in the order `Provider.resolve` tries them.
  #
  # Order is the whole policy: local before shared. A proxy on the loopback
  # costs nothing per call, keeps rail traffic on the machine, and needs no
  # shared credential, so an application with one running should use it without
  # being told to. A gateway is the next choice, and it brings a safety
  # classifier the local one does not have.
  #
  # An application that wants a different order says so with
  # GUARDRAILS_PROVIDER, and an endpoint nobody registered is reachable through
  # GUARDRAILS_API_BASE without touching this file.
  module Providers
    module_function

    def install!(env = ENV)
      Provider.registry.clear
      Provider.register(Llmlite.provider(env))
      Provider.register(Willma.provider(env))
      Provider.registry
    end

    def reset!
      Willma.reset!
      install!
    end
  end
end

NemoGuardrails::Providers.install!
