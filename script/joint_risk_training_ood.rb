# frozen_string_literal: true

module Vangrail
  # Calibration-role fitting for score support and reader disagreement.
  module JointRiskTrainingOod
    module_function

    def normalize_pairs(pairs, feature_schema)
      Array(pairs).map do |pair|
        features = Array(pair).map(&:to_s)
        unless features.size == 2 && features.uniq.size == 2 &&
               features.all? { |feature| feature_schema.include?(feature) }
          raise ArgumentError, "invalid disagreement pair #{pair.inspect}"
        end

        features.sort.freeze
      end.uniq.sort.freeze
    end

    def fit(train, calibration, features, disagreement_pairs, valid_until, epsilon:)
      means = features.to_h { |feature| [feature, mean(train, feature)] }
      scales = features.to_h { |feature| [feature, scale(train, feature, means.fetch(feature), epsilon)] }
      distances = calibration.map { |row| squared_distance(row, means, scales) }
      {
        'feature_means' => means,
        'feature_scales' => scales,
        'max_squared_distance' => [distances.max, epsilon].max,
        'disagreement_rules' => rules(calibration, disagreement_pairs, means, scales, epsilon),
        'calibration_valid_until' => valid_until.to_s,
      }
    end

    def rules(calibration, pairs, means, scales, epsilon)
      pairs.map do |pair|
        differences = calibration.map { |row| standardized_difference(row, pair, means, scales) }
        {
          'features' => pair,
          'max_standardized_difference' => [differences.max, epsilon].max,
        }
      end
    end

    def mean(rows, feature)
      rows.sum { |row| row[:scores].fetch(feature) }.fdiv(rows.size)
    end

    def scale(rows, feature, mean_value, epsilon)
      squared_error = rows.sum { |row| (row[:scores].fetch(feature) - mean_value)**2 }
      value = Math.sqrt(squared_error.fdiv([rows.size - 1, 1].max))
      value > epsilon ? value : 1.0
    end

    def squared_distance(row, means, scales)
      means.sum do |feature, mean_value|
        ((row[:scores].fetch(feature) - mean_value) / scales.fetch(feature))**2
      end
    end

    def standardized_difference(row, pair, means, scales)
      left, right = pair.map do |feature|
        (row[:scores].fetch(feature) - means.fetch(feature)) / scales.fetch(feature)
      end
      (left - right).abs
    end
  end
end
