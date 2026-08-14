# frozen_string_literal: true

require 'minitest/autorun'
require 'tmpdir'
require_relative '../lib/vangrail'
require_relative 'stub_http'

# Shared scaffolding: a rail that answers from a script, and env isolation so a
# developer's own hub token never decides what a test does.
module GuardrailsTest
  # Returns whatever it is told to, and records what it saw.
  class ScriptedRail < Vangrail::Rail
    attr_reader :seen

    def initialize(result, name: 'scripted', sides: Vangrail::Rail::SIDES, offline: true)
      super(name: name, sides: sides)
      @result = result
      @offline = offline
      @seen = []
    end

    def offline?
      @offline
    end

    def call(text, context)
      @seen << { text: text, context: context }
      @result.respond_to?(:call) ? @result.call(text, context) : @result
    end
  end

  # A rail that always raises, for the failure paths.
  class ExplodingRail < Vangrail::Rail
    def initialize(error = Vangrail::TransportError.new('connection refused'), **kwargs)
      super(**kwargs)
      @error = error
    end

    def call(_text, _context)
      raise @error
    end
  end

  ENV_KEYS = %w[
    GUARDRAILS GUARDRAILS_CONFIG GUARDRAILS_CONFIG_ID GUARDRAILS_SERVER GUARDRAILS_SERVER_API_KEY
    GUARDRAILS_MODEL GUARDRAILS_JUDGE_MODEL GUARDRAILS_API_BASE GUARDRAILS_API_KEY GUARDRAILS_RAILS
    GUARDRAILS_ON_ERROR GUARDRAILS_REASONING GUARDRAILS_CACHE
    WILLMA_API_KEY WILLMA_API_KEY_FILE WILLMA_PASS_ENTRY WILLMA_API_BASE
  ].freeze

  def isolate_env!
    @saved_env = ENV_KEYS.to_h { |k| [k, ENV.fetch(k, nil)] }
    ENV_KEYS.each { |k| ENV.delete(k) }
    # Point the file and pass lookups at nothing, so only what a test sets resolves.
    ENV['WILLMA_API_KEY_FILE'] = File.join(Dir.tmpdir, 'guardrails-absent-key')
    ENV['WILLMA_PASS_ENTRY'] = 'guardrails/test/absent-entry'
    Vangrail::Providers.reset!
  end

  def restore_env!
    @saved_env&.each { |k, v| v.nil? ? ENV.delete(k) : ENV[k] = v }
    Vangrail::Providers.reset!
  end
end
