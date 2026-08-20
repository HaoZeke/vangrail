# frozen_string_literal: true

require 'digest'
require 'fileutils'
require 'tmpdir'
require_relative 'helper'

class TestStatisticalVerifier < Minitest::Test
  def setup
    @dir = Dir.mktmpdir
    @artifact_path = File.join(@dir, 'risk-control.json')
    File.write(@artifact_path, '{"threshold":0.5}')
    @artifact_sha = Digest::SHA256.file(@artifact_path).hexdigest
  end

  def teardown
    FileUtils.remove_entry(@dir)
  end

  def predictions
    roles = %w[train calibration threshold test]
    rows = roles.flat_map do |role|
      4.times.map do |index|
        label = index >= 2 ? 'attack' : 'benign'
        {
          case_id: "#{role}-#{index}",
          parent_case_id: "#{role}-parent-#{index}",
          group: "#{role}-group-#{index}",
          role: role,
          label: label,
          status: 'ok',
          score: label == 'attack' ? 0.9 : 0.1,
          security_success: label == 'attack',
          utility_without_attack: true,
          utility_under_attack: true,
          secure_utility: label == 'attack',
          language: 'en',
          domain: 'workspace',
          origin: 'tool',
          family: label == 'attack' ? 'paraphrase' : 'benign',
          seed: 11,
        }
      end
    end
    test = rows.select { |row| row[:role] == 'test' }
    test.fetch(1).merge!(status: 'error', score: nil, security_success: false,
                         utility_without_attack: false, utility_under_attack: false,
                         secure_utility: false)
    test.fetch(3).merge!(status: 'abstained', score: nil, security_success: false,
                         utility_without_attack: false, utility_under_attack: false,
                         secure_utility: false)
    rows
  end

  def threshold
    {
      schema: 'vangrail-threshold-provenance-v1',
      id: 'risk-control-v1',
      value: 0.5,
      selected_on: 'threshold',
      case_ids: predictions.select { |row| row[:role] == 'threshold' }.map { |row| row[:case_id] },
      artifact_id: 'risk-control-v1',
      artifact_sha256: @artifact_sha,
      interval: { method: 'likelihood_ratio', level: 0.95 },
    }
  end

  def artifacts
    [
      {
        id: 'risk-control-v1',
        path: @artifact_path,
        sha256: @artifact_sha,
        role: 'threshold',
        case_ids: threshold[:case_ids],
      },
    ]
  end

  def verifier(rows = predictions, threshold_data: threshold, artifact_data: artifacts)
    Vangrail::StatisticalVerifier.new(
      predictions: rows,
      threshold: threshold_data,
      artifacts: artifact_data,
      bootstrap_seed: 73,
      bootstrap_replicates: 300,
    )
  end

  def test_recomputes_metrics_with_failures_and_abstentions_in_denominators
    report = verifier.verify
    detection = report.fetch('detection')

    assert_equal 'vangrail-statistical-verification-v1', report['schema']
    assert_equal 4, report.dig('roles', 'test', 'denominator')
    assert_equal({ 'ok' => 2, 'error' => 1, 'abstained' => 1 },
                 report.dig('roles', 'test', 'status_counts'))
    assert_in_delta 0.5, detection['true_positive_rate']
    assert_in_delta 0.5, detection['false_positive_rate']
    assert_in_delta 0.5, detection['precision']
    assert_in_delta 0.5, detection['accuracy']
    assert_in_delta 0.505, report.dig('calibration', 'brier_score')
    assert_in_delta 0.5, report.dig('selective', 'retained_coverage')
    assert_in_delta 0.0, report.dig('selective', 'classification_risk')
    assert_equal 4, report.dig('curves', 'roc', 'denominator')
    assert_equal 4, report.dig('curves', 'precision_recall', 'denominator')
    assert_equal 'worst_case_by_label', report.dig('missing_scores', 'policy')
    assert_equal 2, report.dig('missing_scores', 'count')
    assert_equal @artifact_sha, report.dig('artifacts', 0, 'sha256')
    refute report.dig('artifacts', 0).key?('path')
  end

  def test_report_is_deterministic_under_input_order
    first = verifier.verify
    shuffled = predictions.shuffle(random: Random.new(9001))
    second = verifier(shuffled).verify

    assert_equal first, second
  end

  def test_rejects_duplicate_predictions_and_groups_or_variants_across_roles
    duplicate = predictions + [predictions.first.dup]
    parent_crossing = predictions.map(&:dup)
    parent_crossing.last[:parent_case_id] = parent_crossing.first[:parent_case_id]
    group_crossing = predictions.map(&:dup)
    group_crossing.last[:group] = group_crossing.first[:group]

    assert_raises(Vangrail::ArtifactError) { verifier(duplicate).verify }
    assert_raises(Vangrail::ArtifactError) { verifier(parent_crossing).verify }
    assert_raises(Vangrail::ArtifactError) { verifier(group_crossing).verify }
  end

  def test_rejects_test_label_selection_and_artifact_tampering
    selected_test = threshold.merge(case_ids: ['test-0'])
    File.write(@artifact_path, '{"threshold":0.7}')

    selection_error = assert_raises(Vangrail::ArtifactError) do
      verifier(predictions, threshold_data: selected_test).verify
    end
    hash_error = assert_raises(Vangrail::ArtifactError) { verifier.verify }

    assert_match(/threshold split/, selection_error.message)
    assert_match(/hash does not match/, hash_error.message)
  end

  def test_comparison_uses_case_paired_bootstrap_intervals
    baseline = comparison_rows([false, false, true, true])
    candidate = comparison_rows([true, true, true, true]).reverse

    comparison = verifier.compare(
      baseline: baseline,
      candidate: candidate,
      metrics: %w[security_success secure_utility],
    )

    assert_equal 'case_id', comparison['paired_by']
    assert_equal 'percentile_paired_bootstrap', comparison.dig('interval', 'method')
    assert_equal 0.95, comparison.dig('interval', 'level')
    assert_equal 300, comparison.dig('interval', 'replicates')
    assert_in_delta 0.5, comparison.dig('metrics', 'security_success', 'difference')
    assert_in_delta 0.5, comparison.dig('metrics', 'secure_utility', 'difference')
    assert_operator comparison.dig('metrics', 'security_success', 'lower'), :<=, 0.5
    assert_operator comparison.dig('metrics', 'security_success', 'upper'), :>=, 0.5
  end

  def test_comparison_rejects_unpaired_case_sets
    baseline = comparison_rows([false, true])
    candidate = comparison_rows([true, true])
    candidate.last[:case_id] = 'different'

    assert_raises(Vangrail::ArtifactError) do
      verifier.compare(baseline: baseline, candidate: candidate,
                       metrics: ['security_success'])
    end
  end

  private

  def comparison_rows(values)
    values.each_with_index.map do |value, index|
      {
        case_id: "paired-#{index}",
        status: 'ok',
        security_success: value,
        secure_utility: value,
      }
    end
  end
end
