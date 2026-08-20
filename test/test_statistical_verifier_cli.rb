# frozen_string_literal: true

require 'digest'
require 'fileutils'
require 'json'
require 'open3'
require 'rbconfig'
require 'tmpdir'
require_relative 'helper'

class TestStatisticalVerifierCli < Minitest::Test
  def setup
    @dir = Dir.mktmpdir
    @artifact = File.join(@dir, 'threshold-artifact.json')
    File.write(@artifact, '{"threshold":0.5}')
    @artifact_sha = Digest::SHA256.file(@artifact).hexdigest
  end

  def teardown
    FileUtils.remove_entry(@dir)
  end

  def test_cli_atomically_emits_a_json_report_and_regenerated_table
    paths = write_inputs
    _stdout, stderr, status = run_cli(paths)

    assert_predicate status, :success?, stderr
    assert_path_exists paths.fetch(:report)
    assert_path_exists paths.fetch(:table)
    report = JSON.parse(File.read(paths.fetch(:report)))
    table = File.read(paths.fetch(:table))

    assert_equal 'vangrail-statistical-verification-v1', report['schema']
    assert_equal input_sha(paths.fetch(:predictions)), report.dig('inputs', 'predictions', 'sha256')
    assert_equal input_sha(paths.fetch(:threshold)), report.dig('inputs', 'threshold', 'sha256')
    assert_equal input_sha(paths.fetch(:artifacts)), report.dig('inputs', 'artifacts', 'sha256')
    assert_includes table, '| metric | estimate | denominator |'
    assert_includes table, '| secure utility |'
    assert_includes table, '| ROC area |'
    assert_includes table, '| Brier score |'
  end

  def test_cli_publishes_no_partial_output_when_verification_fails
    paths = write_inputs
    artifact = JSON.parse(File.read(paths.fetch(:artifacts)))
    artifact.fetch('artifacts').first['sha256'] = '0' * 64
    File.write(paths.fetch(:artifacts), JSON.pretty_generate(artifact))

    _stdout, stderr, status = run_cli(paths)

    refute_predicate status, :success?
    assert_match(/hash does not match/, stderr)
    refute_path_exists paths.fetch(:report)
    refute_path_exists paths.fetch(:table)
  end

  private

  def write_inputs
    rows = predictions
    paths = {
      predictions: File.join(@dir, 'predictions.jsonl'),
      threshold: File.join(@dir, 'threshold.json'),
      artifacts: File.join(@dir, 'artifacts.json'),
      report: File.join(@dir, 'report.json'),
      table: File.join(@dir, 'table.md'),
    }
    File.write(paths.fetch(:predictions), rows.map { |row| JSON.generate(row) }.join("\n") << "\n")
    File.write(paths.fetch(:threshold), JSON.pretty_generate(threshold(rows)) << "\n")
    File.write(paths.fetch(:artifacts), JSON.pretty_generate(artifact_manifest(rows)) << "\n")
    paths
  end

  def predictions
    %w[train calibration threshold test].flat_map do |role|
      Array.new(4) do |index|
        attack = index >= 2
        {
          case_id: "#{role}-#{index}",
          parent_case_id: "#{role}-parent-#{index}",
          group: "#{role}-group-#{index}",
          role: role,
          label: attack ? 'attack' : 'benign',
          status: 'ok',
          score: attack ? 0.9 : 0.1,
          security_success: attack,
          utility_without_attack: true,
          utility_under_attack: true,
          secure_utility: attack,
          language: 'en',
          domain: 'workspace',
          origin: 'tool',
          family: attack ? 'paraphrase' : 'benign',
          seed: 17,
        }
      end
    end
  end

  def threshold(rows)
    {
      schema: 'vangrail-threshold-provenance-v1',
      id: 'risk-control-v1',
      value: 0.5,
      selected_on: 'threshold',
      case_ids: rows.select { |row| row[:role] == 'threshold' }.map { |row| row[:case_id] },
      artifact_id: 'risk-control-v1',
      artifact_sha256: @artifact_sha,
      interval: { method: 'likelihood_ratio', level: 0.95 },
    }
  end

  def artifact_manifest(rows)
    {
      schema: 'vangrail-artifact-manifest-v1',
      artifacts: [
        {
          id: 'risk-control-v1',
          path: File.basename(@artifact),
          sha256: @artifact_sha,
          role: 'threshold',
          case_ids: rows.select { |row| row[:role] == 'threshold' }.map { |row| row[:case_id] },
        },
      ],
    }
  end

  def run_cli(paths)
    Open3.capture3(
      RbConfig.ruby,
      File.expand_path('../script/verify_evaluation.rb', __dir__),
      '--predictions', paths.fetch(:predictions),
      '--threshold', paths.fetch(:threshold),
      '--artifacts', paths.fetch(:artifacts),
      '--report', paths.fetch(:report),
      '--table', paths.fetch(:table),
      '--bootstrap-seed', '23',
      '--bootstrap-replicates', '200',
    )
  end

  def input_sha(path)
    Digest::SHA256.file(path).hexdigest
  end
end
