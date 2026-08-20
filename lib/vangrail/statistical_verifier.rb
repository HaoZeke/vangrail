# frozen_string_literal: true

require_relative 'artifact_data'
require_relative 'errors'
require_relative 'evaluation_statistics'
require_relative 'paired_statistics'
require_relative 'statistical_validation'

module Vangrail
  # Recomputes evaluation results only after split and artifact invariants hold.
  class StatisticalVerifier
    include ArtifactData
    include StatisticalValidation
    include EvaluationStatistics
    include PairedStatistics

    SCHEMA = 'vangrail-statistical-verification-v1'

    attr_reader :predictions, :threshold, :artifacts,
                :bootstrap_seed, :bootstrap_replicates

    def initialize(predictions:, threshold:, artifacts:, bootstrap_seed:,
                   bootstrap_replicates:)
      @predictions = stringify(predictions).sort_by { |row| row['case_id'].to_s }
      @threshold = stringify(threshold)
      @artifacts = stringify(artifacts)
      @bootstrap_seed = integer(bootstrap_seed, 'bootstrap seed')
      @bootstrap_replicates = positive_integer(bootstrap_replicates, 'bootstrap replicates')
    end

    def verify
      validate_inputs!
      test_rows = predictions.select { |row| row['role'] == 'test' }
      report = {
        'schema' => SCHEMA,
        'roles' => role_summary,
        'threshold' => threshold_summary,
        'artifacts' => @verified_artifacts,
        'missing_scores' => {
          'policy' => 'worst_case_by_label',
          'count' => test_rows.count { |row| row['status'] != 'ok' || row['score'].nil? },
        },
      }
      report.merge(statistics(test_rows))
    end

    def compare(baseline:, candidate:, metrics:)
      paired_comparison(baseline, candidate, metrics)
    end

    private

    def role_summary
      StatisticalValidation::ROLES.to_h do |role|
        rows = predictions.select { |row| row['role'] == role }
        [role, {
          'denominator' => rows.size,
          'labels' => StatisticalValidation::LABELS.to_h do |label|
            [label, rows.count { |row| row['label'] == label }]
          end,
          'status_counts' => status_counts(rows),
        }]
      end
    end

    def threshold_summary
      {
        'schema' => threshold['schema'],
        'id' => threshold['id'],
        'value' => threshold['value'],
        'selected_on' => threshold['selected_on'],
        'case_ids' => threshold['case_ids'].sort,
        'artifact_id' => threshold['artifact_id'],
        'artifact_sha256' => threshold['artifact_sha256'],
        'interval' => threshold['interval'],
      }
    end

    def integer(value, name)
      return value if value.is_a?(Integer)

      raise ArgumentError, "#{name} must be an integer"
    end

    def positive_integer(value, name)
      number = integer(value, name)
      return number if number.positive?

      raise ArgumentError, "#{name} must be positive"
    end
  end
end
