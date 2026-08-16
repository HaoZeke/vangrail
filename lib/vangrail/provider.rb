# frozen_string_literal: true

require_relative 'chat'
require_relative 'completion'
require_relative 'embeddings'
require_relative 'errors'
require_relative 'http'
require_relative 'providers/gateway'

module Vangrail
  # Where the model-backed rails call, and what they may ask for there.
  #
  # Every endpoint this gem talks to is OpenAI-compatible, so the differences
  # that matter are not protocol at all. They are: how a credential resolves,
  # whether the endpoint is up, and which model roles it can actually serve. A
  # local proxy is named by environment and may need starting; a shared
  # gateway resolves a token from three places and is either up or not; neither
  # necessarily hosts a safety classifier.
  #
  # That last point drives a real decision rather than a label. `model(:guard)`
  # returning nil means the provider has no classifier, and the builder puts a
  # policy rail on the input side instead of pretending a classifier is there.
  #
  #   provider = Vangrail::Provider.resolve          # from the environment
  #   provider.chat(:judge)                                # => Chat, ready to ask
  class Provider
    ROLES = %i[guard judge embed].freeze
    ENDPOINTS = { chat: Chat, embeddings: Embeddings, completion: Completion }.freeze

    # Presets by name, in the order `resolve` tries them.
    def self.registry
      @registry ||= {}
    end

    def self.register(provider)
      registry[provider.name] = provider
      provider
    end

    def self.[](name)
      registry[name.to_s]
    end

    def self.names
      registry.keys
    end

    # Picks a provider from the environment.
    #
    #   GUARDRAILS_PROVIDER=<name>   take this one, and fail loudly if it is
    #                                unknown rather than falling back
    #   GUARDRAILS_API_BASE + key    an endpoint nobody registered
    #   otherwise                    the first registered provider that is
    #                                actually available, in registration order
    #
    # Returning nil is a legitimate answer: no endpoint is reachable, and the
    # caller builds an engine with only the offline rails on it.
    def self.resolve(env = ENV)
      candidates = registry.each_value.to_a + [gateway_in(env)].compact

      wanted = present(env['GUARDRAILS_PROVIDER'])
      if wanted
        found = candidates.detect { |p| p.name == wanted }
        raise ConfigError, "unknown provider #{wanted.inspect}; known: #{names.join(', ')}" unless found

        return found.with_env(env)
      end

      explicit = from_env_pair(env)
      return explicit if explicit

      candidates.map { |p| p.with_env(env) }.detect(&:available?)
    end

    # A gateway described by the environment this call was handed, rather than
    # by the one the registry happened to be installed from. Resolution is
    # then a function of (registry, env), which is what a caller passing an
    # env hash is entitled to assume.
    def self.gateway_in(env)
      return nil if env.equal?(ENV)

      spec = Providers::Gateway.from_environment(env)
      spec && Providers::Gateway.provider(spec, env)
    end

    # An endpoint given directly, which is how anything unregistered is used.
    def self.from_env_pair(env)
      base = present(env['GUARDRAILS_API_BASE'])
      return nil unless base

      new(
        name: 'env',
        base_url: base,
        key_resolver: -> { present(env['GUARDRAILS_API_KEY']) },
        models: { judge: present(env['GUARDRAILS_JUDGE_MODEL']), guard: present(env['GUARDRAILS_MODEL']),
                  embed: present(env['GUARDRAILS_EMBED_MODEL']) },
      )
    end

    def self.present(value)
      s = value.to_s.strip
      s.empty? ? nil : s
    end

    attr_reader :name, :base_url, :models, :guard_preset, :local

    def initialize(name:, base_url:, models: {}, key_resolver: nil, guard_preset: nil,
                   local: false, probe: nil)
      @name = name.to_s
      @base_url = base_url.to_s.sub(/\/+\z/, '')
      @models = models
      @key_resolver = key_resolver
      @guard_preset = guard_preset
      @local = local
      @probe = probe
    end

    # A copy that reads overrides out of an environment. Providers are shared
    # objects in a registry, so nothing mutates in place.
    def with_env(env)
      overrides = {
        judge: self.class.present(env['GUARDRAILS_JUDGE_MODEL']),
        guard: self.class.present(env['GUARDRAILS_MODEL']),
        embed: self.class.present(env['GUARDRAILS_EMBED_MODEL']),
      }.compact
      base = self.class.present(env["#{env_prefix}_API_BASE"]) || base_url
      key = self.class.present(env["#{env_prefix}_API_KEY"])
      return self if overrides.empty? && base == base_url && key.nil?

      self.class.new(
        name: name, base_url: base, models: models.merge(overrides),
        key_resolver: key ? -> { key } : @key_resolver,
        guard_preset: guard_preset, local: local, probe: @probe
      )
    end

    def api_key
      return @api_key if defined?(@api_key)

      @api_key = @key_resolver&.call
    end

    def model(role)
      models[role.to_sym]
    end

    # Can this provider serve a safety classifier, as opposed to an instruct
    # model answering a written policy.
    def guard?
      !model(:guard).nil? && !guard_preset.nil?
    end

    # Can it embed. Named rather than assumed for the same reason `guard?` is:
    # an endpoint serving chat need not serve embeddings, and a rail built on
    # the assumption that it does is a rail that reports an error instead of a
    # verdict. No default model is guessed either, because the name of an
    # embedding model is deployment knowledge and a wrong guess is a 404 per
    # check.
    def embed?
      !model(:embed).nil?
    end

    # Up, and holding a credential. A local endpoint is probed, because a proxy
    # that is not running is the ordinary case rather than a failure.
    def available?
      return false unless api_key || !credential_required?
      return true unless @probe

      @probe.call
    end

    def credential_required?
      !@key_resolver.nil?
    end

    def http
      @http ||= HTTP.new(base_url: base_url, api_key: api_key)
    end

    def chat(role = :judge, **kwargs)
      endpoint(:chat, role, **kwargs)
    end

    def embeddings(role = :embed, **kwargs)
      endpoint(:embeddings, role, **kwargs)
    end

    # Scoring rather than generation, from whichever model answers questions.
    # No separate role: any causal model can score text, and asking a
    # deployment to name a second one for it would be ceremony.
    def completion(role = :judge, **kwargs)
      endpoint(:completion, role, **kwargs)
    end

    def to_h
      {
        'name' => name,
        'base_url' => base_url,
        'models' => models.transform_keys(&:to_s).compact,
        'guard_preset' => guard_preset&.to_s,
        'local' => local,
      }.compact
    end

    def to_s
      "#{name} #{base_url}"
    end

    private

    def endpoint(kind, role, **kwargs)
      name = model(role)
      raise ConfigError, "provider #{self.name} has no #{role} model" unless name

      ENDPOINTS.fetch(kind).new(model: name, http: http, **kwargs)
    end

    def env_prefix
      name.upcase.gsub(/[^A-Z0-9]/, '_')
    end
  end
end
