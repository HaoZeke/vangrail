# frozen_string_literal: true

require_relative 'provider'
require_relative 'providers/llmlite'
require_relative 'providers/gateway'

module Vangrail
  # The provider registry, in the order `Provider.resolve` tries it.
  #
  # Order is the whole policy: local before shared. A proxy on the loopback
  # costs nothing per call, keeps rail traffic on the machine, and needs no
  # shared credential, so an application with one running should use it without
  # being told to.
  #
  # Only vendor-neutral entries are built in. A hostname compiled into this gem
  # is an endpoint every installation inherits whether it can reach it or not,
  # and a credential path compiled in is worse, because it publishes where
  # somebody's secrets live. A shared gateway is therefore registered by the
  # application that has one, or described by environment:
  #
  #   Vangrail::Providers.register_gateway(Gateway::Spec.new(name: 'hub', base_url: '...'))
  #   GUARDRAILS_GATEWAY_API_BASE=...  GUARDRAILS_GATEWAY_API_KEY=...
  #
  # An endpoint needed for a single run needs no registration at all:
  # GUARDRAILS_API_BASE with GUARDRAILS_API_KEY beats the whole registry.
  module Providers
    module_function

    def install!(env = ENV)
      Provider.registry.clear
      Provider.register(Llmlite.provider(env))
      register_environment_gateway(env)
      registered_specs.each { |spec| Provider.register(Gateway.provider(spec, env)) }
      Provider.registry
    end

    # Gateways an application asked for, in the order it asked.
    def registered_specs
      @registered_specs ||= []
    end

    # Registers a shared gateway and returns its Provider. Registering a name
    # twice replaces it, so reloading an application is not a duplicate.
    def register_gateway(spec, env: ENV)
      registered_specs.reject! { |s| s.name == spec.name }
      registered_specs << spec
      Provider.register(Gateway.provider(spec, env))
    end

    def register_environment_gateway(env = ENV)
      spec = Gateway.from_environment(env)
      return nil unless spec

      Provider.register(Gateway.provider(spec, env))
    end

    # Forgets registered gateways along with any cached credential, so a test
    # that points a lookup at nothing gets what it asked for.
    def reset!
      @registered_specs = []
      install!
    end
  end
end

Vangrail::Providers.install!
