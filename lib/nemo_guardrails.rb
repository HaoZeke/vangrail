# frozen_string_literal: true

require_relative 'nemo_guardrails/version'
require_relative 'nemo_guardrails/errors'
require_relative 'nemo_guardrails/http'
require_relative 'nemo_guardrails/verdict'
require_relative 'nemo_guardrails/result'
require_relative 'nemo_guardrails/policies'
require_relative 'nemo_guardrails/willma'
require_relative 'nemo_guardrails/guard_model'
require_relative 'nemo_guardrails/server'
require_relative 'nemo_guardrails/config'
require_relative 'nemo_guardrails/rails'

# Ruby bindings for NVIDIA NeMo Guardrails, plus a server-free path that calls
# the same guard models directly over an OpenAI-compatible endpoint.
#
#   rails = NemoGuardrails.rails                   # from the environment
#   v = rails.check_input('how do I submit a job?')
#   v.allowed?   # => true
#   v.certain?   # => false when no rail actually ran
module NemoGuardrails
  module_function

  # Rails from the environment. See NemoGuardrails::Rails.from_env.
  def rails(env = ENV)
    Rails.from_env(env)
  end

  def server(base_url:, **kwargs)
    Server.new(base_url: base_url, **kwargs)
  end

  def guard_model(**kwargs)
    GuardModel.new(**kwargs)
  end
end
