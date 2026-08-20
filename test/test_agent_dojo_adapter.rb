# frozen_string_literal: true

require 'digest'
require 'fileutils'
require 'json'
require_relative 'helper'

class TestAgentDojoAdapter < Minitest::Test
  PACKAGE_SHA256 = '9eacbc89d996f8656b235ad7b626bcf840b1ace7101174ca62d790c7c6d62956'

  def setup
    @dir = Dir.mktmpdir
    write_trace(user_task: 'user_task_0', attack: nil, injection_task: nil,
                utility: true, security: true)
    write_trace(user_task: 'user_task_0', attack: 'tool_knowledge',
                injection_task: 'injection_task_0', utility: true, security: true)
    write_trace(user_task: 'user_task_0', attack: 'tool_knowledge',
                injection_task: 'injection_task_1', utility: false, security: true,
                error: 'context length exceeded')
  end

  def teardown
    FileUtils.remove_entry(@dir)
  end

  def adapter
    Vangrail::AgentDojoAdapter.new(
      package_version: '0.1.35',
      package_sha256: PACKAGE_SHA256,
      benchmark_version: 'v1.2.2',
    )
  end

  def test_imports_paired_per_case_results_without_dropping_errors
    run = adapter.import(
      @dir,
      model_id: 'target-model-v1',
      defense: 'vangrail-reference-monitor-v1',
      seed: 29,
    ).to_h

    assert_equal 'vangrail-benchmark-run-v1', run.fetch('schema')
    assert_equal 'agentdojo', run.dig('benchmark', 'name')
    assert_equal '0.1.35', run.dig('benchmark', 'package_version')
    assert_equal PACKAGE_SHA256, run.dig('benchmark', 'package_sha256')
    assert_equal 'v1.2.2', run.dig('benchmark', 'version')
    assert_equal 'agentdojo-traces-v0.1.35', run.dig('adapter', 'id')
    assert_equal 'target-model-v1', run.dig('target', 'model_id')
    assert_equal 'vangrail-reference-monitor-v1', run.dig('target', 'defense')
    assert_equal 29, run['seed']

    assert_equal 2, run.fetch('cases').size
    assert_case_success(run.fetch('cases').first)
    assert_case_error(run.fetch('cases').last)
    assert_equal({ 'ok' => 1, 'error' => 1, 'abstained' => 0 }, run['status_counts'])
    assert_equal 2, run['denominator']
  end

  def test_source_manifest_covers_every_trace_with_stable_hashes
    run = adapter.import(@dir, model_id: 'm', defense: 'd', seed: 1).to_h
    source = run.fetch('source')

    assert_equal 'sha256-tree-v1', source['schema']
    assert_match(/\A[0-9a-f]{64}\z/, source.fetch('sha256'))
    assert_equal 3, source.fetch('files').size
    assert_equal source.fetch('files').sort_by { |row| row.fetch('path') }, source.fetch('files')
    source.fetch('files').each do |row|
      path = File.join(@dir, row.fetch('path'))

      assert_equal Digest::SHA256.file(path).hexdigest, row.fetch('sha256')
    end
  end

  def test_rejects_trace_versions_outside_the_pinned_contract
    path = trace_path(user_task: 'user_task_0', attack: 'tool_knowledge',
                      injection_task: 'injection_task_0')
    trace = JSON.parse(File.read(path))
    trace['agentdojo_package_version'] = '0.1.36'
    File.write(path, JSON.pretty_generate(trace))

    error = assert_raises(Vangrail::ArtifactError) do
      adapter.import(@dir, model_id: 'm', defense: 'd', seed: 1)
    end

    assert_match(/package version.*0\.1\.36.*0\.1\.35/i, error.message)
  end

  def test_rejects_missing_baseline_and_mixed_attack_runs
    FileUtils.remove_entry(trace_path(user_task: 'user_task_0', attack: nil,
                                      injection_task: nil))
    write_trace(user_task: 'user_task_0', attack: 'important_instructions',
                injection_task: 'injection_task_2', utility: true, security: false)

    error = assert_raises(Vangrail::ArtifactError) do
      adapter.import(@dir, model_id: 'm', defense: 'd', seed: 1)
    end

    assert_match(/one attack/i, error.message)
  end

  def test_builds_the_official_cli_as_argv_with_every_versioned_selector
    argv = adapter.command(
      python: '/opt/agentdojo/bin/python',
      logdir: '/results/run 1',
      model: 'gemini-2.0-flash-001',
      model_id: 'deployment/model',
      attack: 'tool_knowledge',
      defense: 'tool_filter',
      suites: %w[workspace banking],
      user_tasks: %w[user_task_0 user_task_2],
      injection_tasks: ['injection_task_1'],
      modules: ['experiment.adapters'],
      max_workers: 1,
      force_rerun: true,
    )

    assert_equal [
      '/opt/agentdojo/bin/python', '-m', 'agentdojo.scripts.benchmark',
      '--benchmark-version', 'v1.2.2', '--logdir', '/results/run 1',
      '--model', 'gemini-2.0-flash-001', '--model-id', 'deployment/model',
      '--attack', 'tool_knowledge', '--defense', 'tool_filter',
      '--max-workers', '1', '--force-rerun',
      '-s', 'workspace', '-s', 'banking',
      '-ut', 'user_task_0', '-ut', 'user_task_2',
      '-it', 'injection_task_1', '-ml', 'experiment.adapters'
    ], argv
  end

  private

  def assert_case_success(row)
    assert_equal 'workspace/user_task_0/injection_task_0', row['case_id']
    assert_equal 'workspace/user_task_0', row['parent_case_id']
    assert_equal 'ok', row['status']
    assert row['utility_without_attack']
    assert row['utility_under_attack']
    assert row['reported_security']
    assert row['security_success']
    refute row['attack_success']
    assert row['secure_utility']
    assert_match(/\A[0-9a-f]{64}\z/, row.fetch('trace_sha256'))
    assert_match(/\A[0-9a-f]{64}\z/, row.fetch('baseline_trace_sha256'))
  end

  def assert_case_error(row)
    assert_equal 'workspace/user_task_0/injection_task_1', row['case_id']
    assert_equal 'error', row['status']
    assert_equal 'context length exceeded', row['error']
    refute row['security_success']
    refute row['attack_success']
    refute row['secure_utility']
  end

  def write_trace(user_task:, attack:, injection_task:, utility:, security:, error: nil)
    path = trace_path(user_task: user_task, attack: attack, injection_task: injection_task)
    FileUtils.mkdir_p(File.dirname(path))
    File.write(path, JSON.pretty_generate(
                       suite_name: 'workspace',
                       pipeline_name: 'vangrail_pipeline',
                       user_task_id: user_task,
                       injection_task_id: injection_task,
                       attack_type: attack,
                       injections: injection_task ? { 'document' => 'payload' } : {},
                       messages: [
                         { role: 'user', content: [{ type: 'text', content: 'task' }] },
                         { role: 'assistant', content: [{ type: 'text', content: 'answer' }] },
                       ],
                       error: error,
                       benchmark_version: 'v1.2.2',
                       agentdojo_package_version: '0.1.35',
                       duration: 0.25,
                       utility: utility,
                       security: security,
                     ))
  end

  def trace_path(user_task:, attack:, injection_task:)
    attack_dir = attack || 'none'
    injection_file = injection_task || 'none'
    File.join(@dir, 'vangrail_pipeline', 'workspace', user_task,
              attack_dir, "#{injection_file}.json")
  end
end
