# frozen_string_literal: true

require 'digest'
require 'json'
require 'open3'
require 'rbconfig'
require 'tmpdir'
require_relative 'helper'

class TestJointRiskCli < Minitest::Test
  ROLES = { train: 24, calibration: 12, threshold: 12, test: 12 }.freeze

  def cases
    ROLES.flat_map do |role, count|
      Array.new(count) do |index|
        attack = index >= count / 2
        direction = attack ? 1.0 : -1.0
        {
          id: "#{role}-#{index}",
          group: "#{role}-group-#{index}",
          role: role,
          label: attack ? :attack : :benign,
          threat_family: index.even? ? :override : :exfiltration,
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

  def config
    {
      id: 'joint-cli-v1',
      readers: {
        lexical: { model_id: 'lexical-v1', feature_schema: ['score'] },
        encoder: { model_id: 'encoder-v1', feature_schema: ['score'] },
      },
      normalization: { id: 'vangrail-nlp-v1' },
      interactions: [['lexical.score', 'encoder.score']],
      disagreement_pairs: [['lexical.score', 'encoder.score']],
      calibration_valid_until: '2030-01-01T00:00:00Z',
      max_false_positive_rate: 0.5,
      iterations: 80,
      model_card: {
        distribution: 'synthetic grouped test cases',
        assumptions: ['role groups are exchangeable within the named distribution'],
      },
    }
  end

  def test_cli_emits_checked_artifact_report_model_card_and_split_manifest
    Dir.mktmpdir do |dir|
      paths = write_inputs(dir)
      stdout, stderr, status = run_cli(paths)

      assert_predicate status, :success?, stderr
      assert_empty stdout
      outputs(paths).each { |path| assert_path_exists path }
      manifest = JSON.parse(File.read(paths.fetch(:manifest)))
      card = JSON.parse(File.read(paths.fetch(:model_card)))
      report = JSON.parse(File.read(paths.fetch(:report)))
      artifact_sha = Digest::SHA256.file(paths.fetch(:artifact)).hexdigest
      artifact = Vangrail::JointRiskArtifact.load(
        paths.fetch(:artifact),
        expected_sha256: artifact_sha,
      )

      assert_manifest(manifest, artifact_sha)
      assert_model_card(card, artifact, artifact_sha)
      assert_equal ROLES.transform_keys(&:to_s), report['role_counts']
    end
  end

  def assert_manifest(manifest, artifact_sha)
    assert_equal 'vangrail-joint-risk-training-manifest-v1', manifest['schema']
    assert_equal artifact_sha, manifest.dig('outputs', 'artifact', 'sha256')
    assert_equal ROLES.transform_keys(&:to_s), manifest['role_counts']
    assert_equal(60, manifest.fetch('splits').values.sum { |split| split.fetch('case_ids').size })
  end

  def assert_model_card(card, artifact, artifact_sha)
    assert_equal 'vangrail-joint-risk-model-card-v1', card['schema']
    assert_equal artifact.id, card['artifact_id']
    assert_equal artifact_sha, card['artifact_file_sha256']
    assert_equal config.dig(:model_card, :assumptions), card['assumptions']
  end

  def test_cli_does_not_publish_partial_outputs_when_training_fails
    Dir.mktmpdir do |dir|
      rows = cases
      rows[ROLES[:train]][:group] = rows.first[:group]
      paths = write_inputs(dir, rows: rows)

      _stdout, stderr, status = run_cli(paths)

      refute_predicate status, :success?
      assert_match(/group.*roles/, stderr)
      outputs(paths).each { |path| refute_path_exists path }
    end
  end

  private

  def write_inputs(dir, rows: cases)
    paths = {
      cases: File.join(dir, 'cases.jsonl'),
      config: File.join(dir, 'config.json'),
      artifact: File.join(dir, 'artifact.json'),
      report: File.join(dir, 'report.json'),
      model_card: File.join(dir, 'model-card.json'),
      manifest: File.join(dir, 'manifest.json'),
    }
    File.write(paths.fetch(:cases), rows.map { |row| JSON.generate(row) }.join("\n") << "\n")
    File.write(paths.fetch(:config), JSON.pretty_generate(config) << "\n")
    paths
  end

  def run_cli(paths)
    Open3.capture3(
      RbConfig.ruby,
      File.expand_path('../script/train_joint_risk.rb', __dir__),
      '--cases', paths.fetch(:cases),
      '--config', paths.fetch(:config),
      '--artifact', paths.fetch(:artifact),
      '--report', paths.fetch(:report),
      '--model-card', paths.fetch(:model_card),
      '--manifest', paths.fetch(:manifest)
    )
  end

  def outputs(paths)
    paths.values_at(:artifact, :report, :model_card, :manifest)
  end
end
