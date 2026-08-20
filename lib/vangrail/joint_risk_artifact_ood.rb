# frozen_string_literal: true

require 'time'

module Vangrail
  # Validation for score support and calibration lifetime in a risk artifact.
  module JointRiskArtifactOod
    private

    def validate_ood!
      ood = data['ood']
      required = %w[
        feature_means feature_scales max_squared_distance disagreement_rules calibration_valid_until
      ]
      unless ood.is_a?(Hash) && ood.keys.sort == required.sort
        raise ProtocolError, 'ood must name feature distribution, disagreement rules, and calibration expiry'
      end

      validate_numeric_table!('OOD feature means', ood['feature_means'],
                              allowed: feature_schema, exact: true)
      validate_numeric_table!('OOD feature scales', ood['feature_scales'],
                              allowed: feature_schema, exact: true)
      unless ood['feature_scales'].values.all?(&:positive?)
        raise ProtocolError, 'OOD feature scales must be positive'
      end
      validate_finite!('OOD maximum squared distance', ood['max_squared_distance'])
      raise ProtocolError, 'OOD maximum squared distance must be positive' unless ood['max_squared_distance'].positive?

      validate_disagreement_rules!(ood['disagreement_rules'])
      validate_calibration_expiry!(ood['calibration_valid_until'])
    end

    def validate_disagreement_rules!(rules)
      limit = JointRiskArtifact::MAX_DISAGREEMENT_RULES
      unless rules.is_a?(Array) && rules.size <= limit
        raise ProtocolError, "OOD disagreement_rules must contain at most #{limit} entries"
      end

      rules.each do |rule|
        unless rule.is_a?(Hash) && rule.keys.sort == %w[features max_standardized_difference]
          raise ProtocolError, 'an OOD disagreement rule must name features and a maximum difference'
        end
        features = rule['features']
        unless features.is_a?(Array) && features.size == 2 && features.uniq.size == 2 &&
               features.all? { |feature| feature_schema.include?(feature) }
          raise ProtocolError, 'an OOD disagreement rule must name two distinct artifact features'
        end
        limit_value = rule['max_standardized_difference']
        unless finite?(limit_value) && limit_value.positive?
          raise ProtocolError, 'an OOD disagreement maximum must be finite and positive'
        end
      end
    end

    def validate_calibration_expiry!(value)
      Time.iso8601(value.to_s)
    rescue ArgumentError
      raise ProtocolError, 'calibration_valid_until must be an ISO 8601 timestamp'
    end
  end
end
