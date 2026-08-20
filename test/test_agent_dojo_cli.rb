# frozen_string_literal: true

require 'fileutils'
require 'json'
require 'open3'
require 'rbconfig'
require 'tmpdir'
require_relative 'helper'

class TestAgentDojoCli < Minitest::Test
  def setup
    @dir = Dir.mktmpdir
    @logdir = File.join(@dir, 'runs')
    @output = File.join(@dir, 'agentdojo-run.json')
    write_trace(attack: nil, injection_task: nil, utility: true, security: true)
    write_trace(attack: 'tool_knowledge', injection_task: 'injection_task_0',
                utility: true, security: true)
  end

  def teardown
    FileUtils.remove_entry(@dir)
  end

  def test_cli_imports_the_pinned_trace_tree
    stdout, stderr, status = run_cli

    assert_predicate status, :success?, stderr
    assert_empty stdout
    run = JSON.parse(File.read(@output))

    assert_equal 'vangrail-benchmark-run-v1', run['schema']
    assert_equal '0.1.35', run.dig('benchmark', 'package_version')
    assert_equal 'v1.2.2', run.dig('benchmark', 'version')
    assert_equal 1, run['denominator']
    assert_equal 'workspace/user_task_0/injection_task_0', run.dig('cases', 0, 'case_id')
  end

  def test_cli_publishes_nothing_for_a_mismatched_trace_version
    path = trace_path(attack: 'tool_knowledge', injection_task: 'injection_task_0')
    trace = JSON.parse(File.read(path))
    trace['agentdojo_package_version'] = '0.1.34'
    File.write(path, JSON.pretty_generate(trace))

    _stdout, stderr, status = run_cli

    refute_predicate status, :success?
    assert_match(/package version/, stderr)
    refute_path_exists @output
  end

  private

  def run_cli
    Open3.capture3(
      RbConfig.ruby,
      File.expand_path('../script/import_agentdojo.rb', __dir__),
      '--logdir', @logdir,
      '--output', @output,
      '--model-id', 'model-v1',
      '--defense', 'reference-monitor-v1',
      '--seed', '31'
    )
  end

  def write_trace(attack:, injection_task:, utility:, security:)
    path = trace_path(attack: attack, injection_task: injection_task)
    FileUtils.mkdir_p(File.dirname(path))
    File.write(path, JSON.pretty_generate(
                       suite_name: 'workspace',
                       pipeline_name: 'vangrail_pipeline',
                       user_task_id: 'user_task_0',
                       injection_task_id: injection_task,
                       attack_type: attack,
                       injections: injection_task ? { 'document' => 'payload' } : {},
                       messages: [
                         { role: 'user', content: [{ type: 'text', content: 'task' }] },
                         { role: 'assistant', content: [{ type: 'text', content: 'answer' }] },
                       ],
                       error: nil,
                       benchmark_version: 'v1.2.2',
                       agentdojo_package_version: '0.1.35',
                       duration: 0.25,
                       utility: utility,
                       security: security,
                     ))
  end

  def trace_path(attack:, injection_task:)
    File.join(
      @logdir,
      'vangrail_pipeline',
      'workspace',
      'user_task_0',
      attack || 'none',
      "#{injection_task || 'none'}.json",
    )
  end
end
