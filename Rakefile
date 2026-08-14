# frozen_string_literal: true

desc 'Run the unit tests (stdlib minitest, no network)'
task :test do
  files = Dir[File.expand_path('test/test_*.rb', __dir__)]
  files.each { |f| sh Gem.ruby, f }
end

task default: :test
