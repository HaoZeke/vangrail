# frozen_string_literal: true

# One process, one count. `ruby -Ilib test/test_engine.rb` still works for a
# single file. This is what `rake test` loads so SimpleCov sees the whole
# library and minitest reports a number that is not the last file's.
require_relative 'helper'

Dir[File.join(__dir__, 'test_*.rb')].each { |file| require file }
