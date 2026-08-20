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
    local proxy. Reads folders in the NeMo layout and executes a documented
    Colang 1.0 rail-flow subset in process. A NeMo folder is not drop-in.
    Optional client for teams who already run the Python server. Standard
    library only.
  TEXT
  spec.authors = ['Rohit Goswami']
  spec.email = ['rohit.goswami@surf.nl']
  spec.license = 'MIT'
  spec.required_ruby_version = '>= 3.1'
  spec.homepage = 'https://github.com/HaoZeke/vangrail'

  spec.files = Dir['lib/**/*.rb', 'lib/**/*.json'] + %w[README.md LICENSE] + Dir['exe/*']
  spec.bindir = 'exe'
  spec.executables = ['vangrail']
  spec.require_paths = ['lib']

  spec.metadata['homepage_uri'] = spec.homepage
  spec.metadata['source_code_uri'] = "#{spec.homepage}/tree/main"
  spec.metadata['changelog_uri'] = 'https://github.com/HaoZeke/vangrail/blob/main/CHANGELOG.md'
  spec.metadata['bug_tracker_uri'] = 'https://github.com/HaoZeke/vangrail/issues'
  spec.metadata['allowed_push_host'] = 'https://rubygems.org'
  spec.metadata['rubygems_mfa_required'] = 'true'

  # Development only, and deliberately so. unicode-confusable supplies the
  # Unicode confusables data that script/generate_confusables.rb turns into
  # lib/vangrail/confusables_data.rb. The table is checked in, so an installed
  # gem needs nothing but the standard library, and the data still comes from
  # UTS #39 rather than from somebody's memory of it.
  spec.add_development_dependency 'unicode-confusable', '~> 1.13'
end
