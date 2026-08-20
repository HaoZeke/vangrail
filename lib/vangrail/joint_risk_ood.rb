# frozen_string_literal: true

require 'time'

module Vangrail
  # Artifact-calibrated support checks for joint-risk inference.
  module JointRiskOod
    private

    def validate_calibration_age!
      expiry = Time.iso8601(artifact.ood.fetch('calibration_valid_until'))
      observed_at = clock.call
      raise JointRiskModel::Abstention, 'risk model clock did not return a Time' unless observed_at.is_a?(Time)
      return unless observed_at > expiry

      raise JointRiskModel::Abstention, "calibration expired at #{expiry.utc.iso8601}"
    end

    def validate_ood!(features)
      distance = squared_distance(features)
      if distance > artifact.ood.fetch('max_squared_distance')
        raise JointRiskModel::Abstention, "score-vector distance #{distance} exceeds calibrated support"
      end

      artifact.ood.fetch('disagreement_rules').each do |rule|
        difference = standardized_difference(features, rule.fetch('features'))
        next if difference <= rule.fetch('max_standardized_difference')

        raise JointRiskModel::Abstention,
              "reader disagreement #{difference} exceeds calibrated support"
      end
    end

    def squared_distance(features)
      means = artifact.ood.fetch('feature_means')
      scales = artifact.ood.fetch('feature_scales')
      features.sum do |name, value|
        ((value - means.fetch(name)) / scales.fetch(name))**2
      end
    end

    def standardized_difference(features, names)
      means = artifact.ood.fetch('feature_means')
      scales = artifact.ood.fetch('feature_scales')
      left, right = names.map do |name|
        (features.fetch(name) - means.fetch(name)) / scales.fetch(name)
      end
      (left - right).abs
    end
  end
end
