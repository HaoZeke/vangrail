# frozen_string_literal: true

module Vangrail
  # Optional Magnus extension. The gem stays installable without a compiler;
  # this module is present only after `vangrail-native` is built.
  module Native
    module_function

    def available?
      load_ext
      @available
    end

    def load_ext
      return if defined?(@available)

      require 'vangrail_native'
      @available = true
    rescue LoadError
      @available = false
    end
  end
end
