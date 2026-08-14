# frozen_string_literal: true

require_relative 'lib/vangrail/version'

Gem::Specification.new do |spec|
  spec.name = 'vangrail'
  spec.version = Vangrail::VERSION
  spec.summary = 'Guardrails that run in your Ruby process: input and output rails, no Python service'
  spec.description = <<~TEXT
    Input and output rails as ordinary Ruby objects, returning passed, modified,
    or blocked, and reporting whether a rail actually reached the decision.
    Deterministic rails need no network at all; model-backed ones call any
    OpenAI-compatible endpoint through a provider abstraction that prefers a
    local proxy. Reads and writes NeMo Guardrails configuration folders and
    executes their Colang flows in process, with an optional client for teams
    who already run the Python server. Standard library only.
  TEXT
  spec.authors = ['Rohit Goswami']
  spec.email = ['rohit.goswami@surf.nl']
  spec.license = 'MIT'
  spec.required_ruby_version = '>= 3.1'

  spec.files = Dir['lib/**/*.rb'] + %w[README.md LICENSE]
  spec.require_paths = ['lib']

  spec.metadata['rubygems_mfa_required'] = 'true'
end
