# frozen_string_literal: true

module Vangrail
  # Canonical immutable representation shared by bounded JSON artifacts.
  module ArtifactData
    private

    def stringify(value)
      case value
      when Hash then value.to_h { |key, nested| [key.to_s, stringify(nested)] }
      when Array then value.map { |nested| stringify(nested) }
      when Symbol then value.to_s
      else value
      end
    end

    def immutable(value)
      case value
      when Hash then value.to_h { |key, nested| [key.freeze, immutable(nested)] }.freeze
      when Array then value.map { |nested| immutable(nested) }.freeze
      when String then value.freeze
      else value.freeze
      end
    end

    def canonical(value)
      JSON.generate(sort_hashes(value))
    end

    def sort_hashes(value)
      case value
      when Hash then value.keys.sort.to_h { |key| [key, sort_hashes(value[key])] }
      when Array then value.map { |nested| sort_hashes(nested) }
      else value
      end
    end
  end
end
