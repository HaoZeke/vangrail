# frozen_string_literal: true

require 'json'

module Vangrail
  # Canonical JSON conversion for deterministic joint-training manifests.
  module JointRiskTrainingData
    module_function

    def canonical(value)
      JSON.generate(sort_value(stringify(value)))
    end

    def stringify(value)
      case value
      when Hash then value.to_h { |key, nested| [key.to_s, stringify(nested)] }
      when Array then value.map { |nested| stringify(nested) }
      when Symbol then value.to_s
      else value
      end
    end

    def sort_value(value)
      case value
      when Hash then value.keys.sort.to_h { |key| [key, sort_value(value[key])] }
      when Array then value.map { |nested| sort_value(nested) }
      else value
      end
    end
  end
end
