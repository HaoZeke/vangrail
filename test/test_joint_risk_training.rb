# frozen_string_literal: true

require_relative 'helper'
require_relative '../script/joint_risk_training'

class TestJointRiskTraining < Minitest::Test
  ROLES = { train: 24, calibration: 12, test: 12 }.freeze

  def cases
    ROLES.flat_map do |role, count|
      Array.new(count) do |index|
        attack = index >= count / 2
        direction = attack ? 1.0 : -1.0
        threat_family = index.even? ? :override : :exfiltration
        {
          id: "#{role}-#{index}",
          group: "#{role}-group-#{index}",
          role: role,
          label: attack ? :attack : :benign,
          threat_family: threat_family,
          scores: {
            'lexical.score' => direction * (0.8 + (index % 3 * 0.05)),
            'encoder.score' => direction * (1.0 + (index % 2 * 0.05)),
          },
          side: :context,
          origin: :data,
          language: :en,
          domain: :handbook,
        }
      end
    end
  end

  def readers
    {
      lexical: { model_id: 'lexical-v1', feature_schema: ['score'] },
      encoder: { model_id: 'encoder-v1', feature_schema: ['score'] },
    }
  end

  def fit(rows = cases)
    Vangrail::JointRiskTraining.fit(
      rows,
      id: 'joint-trained-v1',
      readers: readers,
      normalization: { id: 'vangrail-nlp-v1' },
      interactions: [['lexical.score', 'encoder.score']],
      iterations: 80,
    )
  end

  def test_trainer_emits_a_loadable_laplace_artifact_and_final_test_report
    artifact, report = fit

    assert_instance_of Vangrail::JointRiskArtifact, artifact
    assert_equal 'laplace_diagonal', artifact.posterior_method
    assert_equal 'platt', artifact.calibration['method']
    assert_equal %w[exfiltration override], artifact.threat_model['training_composition'].keys.sort
    assert_in_delta 1.0, artifact.threat_model['training_composition'].values.sum
    assert_equal ROLES.transform_keys(&:to_s), report.fetch('role_counts')
    assert_equal 12, report.dig('test', 'cases')
    assert_operator report.dig('test', 'brier'), :<, 0.25
    assert_match(/\A[0-9a-f]{64}\z/, artifact.data['training_manifest_sha256'])
  end

  def test_final_test_labels_cannot_change_the_artifact
    artifact, report = fit
    relabelled = cases.map do |row|
      next row unless row[:role] == :test

      row.merge(label: row[:label] == :attack ? :benign : :attack)
    end
    changed_artifact, changed_report = fit(relabelled)

    assert_equal artifact.sha256, changed_artifact.sha256
    refute_equal report.dig('test', 'brier'), changed_report.dig('test', 'brier')
  end

  def test_calibration_labels_change_the_calibration_artifact
    artifact, = fit
    relabelled = cases.map do |row|
      next row unless row[:role] == :calibration

      row.merge(label: row[:label] == :attack ? :benign : :attack)
    end
    changed, = fit(relabelled)

    refute_equal artifact.sha256, changed.sha256
  end

  def test_groups_cannot_cross_evaluation_roles
    rows = cases
    rows[ROLES[:train]][:group] = rows.first[:group]

    error = assert_raises(ArgumentError) { fit(rows) }

    assert_match(/group.*roles/, error.message)
  end
end
