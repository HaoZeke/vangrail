# frozen_string_literal: true

require 'json'
require_relative 'artifact_data'
require_relative 'beta'
require_relative 'errors'
require_relative 'judgement'

module Vangrail
  # One-sided binomial risk control fitted only on threshold-role cases.
  class RiskControl
    include ArtifactData

    SCHEMA = 'vangrail-risk-control-v1'
    METHOD = 'learn_then_test_binomial'
    FIELDS = %w[
      schema method block_at max_false_positive_rate confidence benign_cases false_positives
      false_positive_upper_bound calibration_manifest_sha256
    ].freeze

    attr_reader :data

    def initialize(raw)
      raise ProtocolError, 'risk control must be a hash' unless raw.is_a?(Hash)

      @data = stringify(raw)
      validate!
      @data = immutable(@data)
      freeze
    end

    def self.fit(predictions, max_false_positive_rate:, confidence:,
                 calibration_manifest_sha256:)
      rows = normalize_predictions(predictions)
      validate_predictions!(rows)
      maximum = probability(max_false_positive_rate, 'max_false_positive_rate')
      mass = probability(confidence, 'confidence')
      benign = rows.select { |row| row.fetch('label') == 'benign' }
      threshold, false_positives, upper = select_threshold(benign, maximum, mass)
      raise ProtocolError, 'threshold cases cannot certify the requested false-positive rate' unless threshold

      new(
        'schema' => SCHEMA,
        'method' => METHOD,
        'block_at' => threshold,
        'max_false_positive_rate' => maximum,
        'confidence' => mass,
        'benign_cases' => benign.size,
        'false_positives' => false_positives,
        'false_positive_upper_bound' => upper,
        'calibration_manifest_sha256' => calibration_manifest_sha256,
      )
    end

    def schema = data.fetch('schema')
    def method = data.fetch('method')
    def block_at = data.fetch('block_at')
    def max_false_positive_rate = data.fetch('max_false_positive_rate')
    def confidence = data.fetch('confidence')
    def benign_cases = data.fetch('benign_cases')
    def false_positives = data.fetch('false_positives')
    def false_positive_upper_bound = data.fetch('false_positive_upper_bound')
    def calibration_manifest_sha256 = data.fetch('calibration_manifest_sha256')

    def policy(review_at: block_at)
      unless review_at.is_a?(Numeric) && review_at.finite? && review_at >= 0 && review_at <= block_at
        raise ArgumentError, 'review_at must be finite and between zero and block_at'
      end

      Policy.new(block_at: block_at, review_at: review_at)
    end

    def to_h
      data
    end

    class << self
      private

      def normalize_predictions(predictions)
        Array(predictions).map do |raw|
          raise ArgumentError, 'a threshold prediction must be a hash' unless raw.is_a?(Hash)

          raw.to_h { |name, value| [name.to_s, value.is_a?(Symbol) ? value.to_s : value] }
        end
      end

      def validate_predictions!(rows)
        raise ArgumentError, 'risk control needs threshold predictions' if rows.empty?
        unless rows.all? { |row| row['role'] == 'threshold' }
          raise ArgumentError, 'risk control requires only threshold-role predictions'
        end
        unless rows.all? { |row| %w[attack benign].include?(row['label']) && valid_score?(row['posterior']) }
          raise ArgumentError, 'threshold predictions need binary labels and finite posteriors'
        end

        ids = rows.map { |row| row['id'].to_s }
        raise ArgumentError, 'threshold prediction ids must be unique' unless ids.all? do |id|
          !id.empty?
        end && ids.uniq == ids
        raise ArgumentError, 'risk control needs benign threshold cases' unless rows.any? do |row|
          row['label'] == 'benign'
        end
      end

      def select_threshold(benign, maximum, confidence)
        candidates = [0.0, 1.0] + benign.filter_map do |row|
          candidate = row.fetch('posterior').next_float
          candidate if candidate <= 1.0
        end
        candidates.uniq.sort.each do |threshold|
          failures = benign.count { |row| row.fetch('posterior') >= threshold }
          upper = binomial_upper(failures, benign.size, confidence)
          return [threshold, failures, upper] if upper <= maximum
        end
        nil
      end

      def binomial_upper(failures, cases, confidence)
        return 1.0 if failures == cases

        Beta.quantile(confidence, failures + 1, cases - failures)
      end

      def probability(value, name)
        return value if valid_score?(value) && value.positive? && value < 1

        raise ArgumentError, "#{name} must be finite and strictly between zero and one"
      end

      def valid_score?(value)
        value.is_a?(Numeric) && value.finite? && value >= 0 && value <= 1
      end
    end

    private

    def validate!
      raise ProtocolError, 'risk control fields do not match the schema' unless data.keys.sort == FIELDS.sort
      raise ProtocolError, "unsupported risk control schema #{schema.inspect}" unless schema == SCHEMA
      raise ProtocolError, "unsupported risk control method #{method.inspect}" unless method == METHOD

      validate_probabilities!
      validate_counts!
      validate_bound!
      return if calibration_manifest_sha256.match?(/\A[0-9a-f]{64}\z/)

      raise ProtocolError, 'risk control calibration manifest must be a lowercase SHA-256 digest'
    end

    def validate_probabilities!
      values = [block_at, max_false_positive_rate, confidence, false_positive_upper_bound]
      unless values.all? { |value| value.is_a?(Numeric) && value.finite? && value >= 0 && value <= 1 }
        raise ProtocolError, 'risk control probabilities must be finite and between zero and one'
      end
      unless max_false_positive_rate.positive? && max_false_positive_rate < 1 && confidence.positive? && confidence < 1
        raise ProtocolError, 'risk control target and confidence must be strictly between zero and one'
      end
    end

    def validate_counts!
      unless benign_cases.is_a?(Integer) && benign_cases.positive? &&
             false_positives.is_a?(Integer) && false_positives.between?(0, benign_cases)
        raise ProtocolError, 'risk control counts are invalid'
      end
    end

    def validate_bound!
      exact = self.class.send(:binomial_upper, false_positives, benign_cases, confidence)
      if false_positive_upper_bound + 1e-12 < exact
        raise ProtocolError, 'risk control false-positive bound is not conservative'
      end
      return if false_positive_upper_bound <= max_false_positive_rate

      raise ProtocolError, 'risk control does not meet its false-positive target'
    end
  end
end
