# frozen_string_literal: true

require_relative 'lib/nemo_guardrails/version'

Gem::Specification.new do |spec|
  spec.name = 'nemo_guardrails'
  spec.version = NemoGuardrails::VERSION
  spec.summary = 'Ruby bindings for NVIDIA NeMo Guardrails, plus a server-free guard-model path'
  spec.description = <<~TEXT
    Talks to a running NeMo Guardrails server over its OpenAI-compatible REST API,
    and, where no server is available, runs the same input and output rails by
    calling a guard model (Llama Guard 3, AprielGuard, gpt-oss-safeguard) directly
    on any OpenAI-compatible endpoint. Also writes the config folder the Python
    server loads, so one description of a policy serves both paths. Standard
    library only.
  TEXT
  spec.authors = ['Rohit Goswami']
  spec.email = ['rohit.goswami@surf.nl']
  spec.license = 'MIT'
  spec.required_ruby_version = '>= 3.1'

  spec.files = Dir['lib/**/*.rb'] + %w[README.md LICENSE]
  spec.require_paths = ['lib']

  spec.metadata['rubygems_mfa_required'] = 'true'
end
