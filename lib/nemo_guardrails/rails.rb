# frozen_string_literal: true

require_relative 'guard_model'
require_relative 'server'
require_relative 'verdict'
require_relative 'willma'

module NemoGuardrails
  # One entry point for an application that wants rails without caring which
  # backend provides them.
  #
  # Three modes, in the order they are preferred:
  #
  #   :server       a NeMo Guardrails server, when GUARDRAILS_SERVER is set
  #   :guard_model  a guard model over an OpenAI-compatible endpoint
  #   :off          nothing is configured
  #
  # In :off mode every check returns an allowed verdict with certain? false, so
  # a caller that reports its posture can say "not checked" instead of "clean".
  # That distinction is the whole point of the class: an application that treats
  # a missing rail as a pass, silently, has a guardrail on paper only.
  class Rails
    MODES = %i[server guard_model off].freeze
    DEFAULT_RAILS = %i[input output].freeze
    ALL_RAILS = %i[input output grounding].freeze

    attr_reader :mode, :backend, :enabled, :on_error, :judge_model

    def initialize(backend: nil, mode: nil, enabled: DEFAULT_RAILS, on_error: :allow,
                   judge_model: Willma::FALLBACK_JUDGE_MODEL)
      @backend = backend
      @mode = mode || infer_mode(backend)
      @enabled = Array(enabled).map(&:to_sym) & ALL_RAILS
      @on_error = on_error.to_sym
      @judge_model = judge_model
    end

    # Build from the environment:
    #
    #   GUARDRAILS=off              turn every rail off
    #   GUARDRAILS_SERVER=<url>     use a NeMo Guardrails server
    #   GUARDRAILS_CONFIG_ID=<id>   which server config to run
    #   GUARDRAILS_MODEL=<model>    guard model for the direct path
    #   GUARDRAILS_API_BASE=<url>   OpenAI-compatible base for the direct path
    #   GUARDRAILS_RAILS=input,output,grounding
    #   GUARDRAILS_ON_ERROR=allow|block
    def self.from_env(env = ENV)
      common = {
        enabled: parse_rails(env['GUARDRAILS_RAILS']),
        on_error: env['GUARDRAILS_ON_ERROR'].to_s.strip.downcase == 'block' ? :block : :allow,
        judge_model: present(env['GUARDRAILS_JUDGE_MODEL']) || Willma::FALLBACK_JUDGE_MODEL
      }
      return new(backend: nil, mode: :off, **common) if off?(env['GUARDRAILS'])

      server_url = env['GUARDRAILS_SERVER'].to_s.strip
      unless server_url.empty?
        server = Server.new(
          base_url: server_url,
          config_id: present(env['GUARDRAILS_CONFIG_ID']),
          api_key: present(env['GUARDRAILS_SERVER_API_KEY'])
        )
        return new(backend: server, mode: :server, **common)
      end

      api_key = present(env['GUARDRAILS_API_KEY']) || Willma.token
      return new(backend: nil, mode: :off, **common) unless api_key

      guard = GuardModel.new(
        model: present(env['GUARDRAILS_MODEL']),
        base_url: present(env['GUARDRAILS_API_BASE']) || Willma.base_url,
        api_key: api_key,
        reasoning: truthy?(env['GUARDRAILS_REASONING'])
      )
      new(backend: guard, mode: :guard_model, **common)
    end

    def self.off?(value)
      %w[0 off false no].include?(value.to_s.strip.downcase)
    end

    def self.truthy?(value)
      %w[1 on true yes].include?(value.to_s.strip.downcase)
    end

    def self.parse_rails(value)
      text = value.to_s.strip
      return DEFAULT_RAILS if text.empty?
      return [] if off?(text) || text.downcase == 'none'
      return ALL_RAILS.dup if text.downcase == 'all'

      text.split(/[,\s]+/).map { |s| s.strip.downcase.to_sym } & ALL_RAILS
    end

    def self.present(value)
      s = value.to_s.strip
      s.empty? ? nil : s
    end

    def on?(rail)
      mode != :off && enabled.include?(rail.to_sym)
    end

    def check_input(text)
      return skipped(:input) unless on?(:input)

      guarded(:input) { backend.check_input(text) }
    end

    def check_output(text, user_input: nil)
      return skipped(:output) unless on?(:output)

      guarded(:output) { backend.check_output(text, user_input: user_input) }
    end

    # Groundedness needs the passages, which a Colang rail cannot see from here,
    # so this path always uses a guard model even in :server mode.
    def check_grounding(answer, passages:)
      return skipped(:grounding) unless on?(:grounding)

      judge = grounding_backend
      return skipped(:grounding) unless judge

      guarded(:grounding) { judge.check_grounding(answer, passages: passages) }
    end

    # One line for a status endpoint or a log: what is on, and where it runs.
    def describe
      return 'off' if mode == :off

      where = case mode
              when :server then "server #{backend.base_url}#{backend.config_id ? " config=#{backend.config_id}" : ''}"
              else "model #{backend.model}#{reasoning? ? ' reasoning' : ''}"
              end
      "#{where} rails=#{enabled.join(',')} on_error=#{on_error}"
    end

    def reasoning?
      backend.respond_to?(:reasoning) && backend.reasoning == true
    end

    def to_h
      {
        'mode' => mode.to_s,
        'rails' => enabled.map(&:to_s),
        'on_error' => on_error.to_s,
        'model' => (backend.respond_to?(:model) ? backend.model : nil),
        'reasoning' => (reasoning? || nil),
        'server' => (mode == :server ? backend.base_url : nil),
        'config_id' => (mode == :server ? backend.config_id : nil)
      }.compact
    end

    private

    # Grounding needs a model that can answer a policy prompt. A guard-model
    # backend running a classifier preset gets a judge on the same endpoint and
    # credentials; a server backend needs one built from the hub token.
    def grounding_backend
      return @grounding_backend if defined?(@grounding_backend)

      @grounding_backend =
        if backend.is_a?(GuardModel)
          backend.policy_capable? ? backend : backend.policy_judge(judge_model)
        elsif Willma.available?
          GuardModel.new(model: judge_model, preset: :policy, max_tokens: 256)
        end
    end

    def infer_mode(backend)
      case backend
      when Server then :server
      when GuardModel then :guard_model
      else :off
      end
    end

    def skipped(rail)
      Verdict.unchecked(rail: rail, reason: mode == :off ? 'guardrails off' : "#{rail} rail not enabled")
    end

    # A rail that fails is a rail that did not answer. Which way that falls is
    # the operator's call: :allow keeps the desk answering, :block stops it.
    def guarded(rail)
      yield
    rescue Error => e
      reason = "#{rail} rail failed: #{e.class.name.split('::').last}: #{e.message}"
      return Verdict.new(allowed: false, certain: false, rail: rail, reason: reason) if on_error == :block

      Verdict.unchecked(rail: rail, reason: reason)
    end
  end
end
