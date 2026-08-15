# frozen_string_literal: true

desc 'Run the suite in one process (stdlib minitest, no network)'
task :test do
  sh Gem.ruby, '-Ilib:test', File.expand_path('test/suite.rb', __dir__)
end

desc 'Run each test file in its own process (for isolation debugging)'
task 'test:each' do
  Dir[File.expand_path('test/test_*.rb', __dir__)].each do |file|
    sh Gem.ruby, '-Ilib', file
  end
end

task default: :test
