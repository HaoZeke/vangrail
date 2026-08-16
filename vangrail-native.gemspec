# frozen_string_literal: true

require_relative 'lib/vangrail/version'

Gem::Specification.new do |spec|
  spec.name = 'vangrail-native'
  spec.version = Vangrail::VERSION
  spec.summary = 'Optional Magnus kernel for Vangrail::LinearModel#score'
  spec.description = <<~TEXT
    Hashed n-gram bag and the linear dot product, compiled with Magnus and
    rb-sys. Stemming and Unicode folding stay in the vangrail gem so train
    and serve cannot drift. The vangrail gem itself stays standard-library
    only; this extension is optional.
  TEXT
  spec.authors = ['Rohit Goswami']
  spec.email = ['rohit.goswami@surf.nl']
  spec.license = 'MIT'
  spec.required_ruby_version = '>= 3.1'
  spec.homepage = 'https://github.com/HaoZeke/vangrail'

  spec.files = Dir['ext/vangrail_native/**/*', 'lib/vangrail/native.rb']
  spec.extensions = ['ext/vangrail_native/extconf.rb']
  spec.require_paths = ['lib']

  spec.metadata['homepage_uri'] = spec.homepage
  spec.metadata['source_code_uri'] = "#{spec.homepage}/tree/main"
  spec.metadata['allowed_push_host'] = 'https://rubygems.org'
  spec.metadata['rubygems_mfa_required'] = 'true'

  spec.add_dependency 'rb_sys', '~> 0.9'
  spec.add_dependency 'vangrail', spec.version.to_s
end
