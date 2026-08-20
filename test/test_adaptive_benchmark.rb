# frozen_string_literal: true

require 'json'
require 'rbconfig'
require_relative 'helper'

class TestAdaptiveBenchmark < Minitest::Test
  TRACE_SHA = 'a' * 64

  class ScriptedRunner
    attr_reader :requests

    def initialize(responses)
      @responses = responses
      @requests = []
    end

    def run(request)
      @requests << request
      response = @responses.fetch(request.fetch('case').fetch('id'))
      response.respond_to?(:call) ? response.call(request) : response
    end
  end

  def matrix
    Vangrail::AdaptiveAttackMatrix.new(
      schema: 'vangrail-adaptive-attack-matrix-v1',
      id: 'adaptive-campaign-v1',
      version: '1.0.0',
      cases: [
        attack_case(id: 'rewrite-1', family: :paraphrase, access: :black_box,
                    attack_budget: 24),
        attack_case(id: 'probe-1', family: :score_query, access: :score_query,
                    attack_budget: 8),
      ],
    )
  end

  def target
    {
      id: 'target-v1',
      model_id: 'model-v1',
      environment_id: 'tool-environment-v1',
      defense: 'reference-monitor-v1',
    }
  end

  def test_runs_every_case_through_the_external_adversary_and_keeps_abstentions
    runner = ScriptedRunner.new(
      'rewrite-1' => response('rewrite-1', security_success: false,
                                           utility_under_attack: true, queries: 7),
      'probe-1' => {
        schema: 'vangrail-adaptive-response-v1',
        case_id: 'probe-1',
        target_id: 'target-v1',
        adversary: { id: 'score-search', version: '2.1.0', access: 'score_query' },
        status: 'abstained',
        reason: 'search budget exhausted',
        queries: 8,
        model_calls: 8,
        tool_calls: 0,
        duration_seconds: 1.5,
        trace_sha256: TRACE_SHA,
      },
    )

    run = Vangrail::AdaptiveBenchmarkAdapter.new(matrix: matrix, runner: runner)
                                            .run(target: target, seed: 41).to_h

    assert_equal 'vangrail-benchmark-run-v1', run['schema']
    assert_equal 'adaptive-security', run.dig('benchmark', 'name')
    assert_equal 'adaptive-campaign-v1', run.dig('attack', 'matrix_id')
    assert_equal matrix.sha256, run.dig('attack', 'matrix_sha256')
    assert_equal 2, run['denominator']
    assert_equal({ 'ok' => 1, 'error' => 0, 'abstained' => 1 }, run['status_counts'])
    assert_equal(%w[probe-1 rewrite-1], run.fetch('cases').map { |row| row['case_id'] })
    assert_equal 2, runner.requests.size
    assert_request(runner.requests.first)
    assert_success(run.fetch('cases').last)
  end

  def test_invalid_or_failed_runner_results_become_error_rows
    runner = ScriptedRunner.new(
      'rewrite-1' => response('different-case', security_success: true,
                                                utility_under_attack: true, queries: 1),
      'probe-1' => lambda do |_request|
        raise Vangrail::ProtocolError, 'runner exited with status 7'
      end,
    )

    run = Vangrail::AdaptiveBenchmarkAdapter.new(matrix: matrix, runner: runner)
                                            .run(target: target, seed: 41).to_h

    assert_equal 2, run['denominator']
    assert_equal({ 'ok' => 0, 'error' => 2, 'abstained' => 0 }, run['status_counts'])
    run.fetch('cases').each do |row|
      assert_equal 'error', row['status']
      refute row['security_success']
      refute row['secure_utility']
    end
    assert_match(/case identity/, run.fetch('cases').last['error'])
    assert_match(/status 7/, run.fetch('cases').first['error'])
  end

  def test_rejects_duplicate_cases_unknown_families_and_invalid_budgets
    duplicate = [attack_case(id: 'same'), attack_case(id: 'same')]
    unknown = [attack_case(family: :unregistered)]
    invalid_budget = [attack_case(attack_budget: 0)]

    assert_raises(Vangrail::ArtifactError) { matrix_with(duplicate) }
    assert_raises(Vangrail::ArtifactError) { matrix_with(unknown) }
    assert_raises(Vangrail::ArtifactError) { matrix_with(invalid_budget) }
  end

  def test_command_runner_uses_bounded_json_without_a_shell_or_inherited_environment
    ENV['VANGRAIL_TEST_SECRET'] = 'must-not-cross-process-boundary'
    script = <<~RUBY
      require 'json'
      request = JSON.parse($stdin.read)
      row = request.fetch('case')
      puts JSON.generate(
        schema: 'vangrail-adaptive-response-v1',
        case_id: row.fetch('id'),
        target_id: request.dig('target', 'id'),
        adversary: {
          id: 'command-search', version: '1.0.0', access: row.fetch('access'),
          argument: ARGV.fetch(0), inherited_secret: ENV['VANGRAIL_TEST_SECRET'],
        },
        status: 'ok', utility_without_attack: true, utility_under_attack: true,
        security_success: true, attack_success: false, score: 0.1,
        queries: 1, model_calls: 1, tool_calls: 1, duration_seconds: 0.2,
        trace_sha256: '#{TRACE_SHA}',
      )
    RUBY
    runner = Vangrail::AdaptiveRunners::Command.new(
      command: [RbConfig.ruby, '-e', script, '; echo injected'],
      timeout: 2,
    )

    result = runner.run(
      'schema' => 'vangrail-adaptive-request-v1',
      'case' => matrix.to_h.fetch('cases').first,
      'target' => target.transform_keys(&:to_s),
      'seed' => 41,
    )

    assert_equal 'rewrite-1', result['case_id']
    assert_equal '; echo injected', result.dig('adversary', 'argument')
    assert_nil result.dig('adversary', 'inherited_secret')
  ensure
    ENV.delete('VANGRAIL_TEST_SECRET')
  end

  private

  def matrix_with(cases)
    Vangrail::AdaptiveAttackMatrix.new(
      schema: 'vangrail-adaptive-attack-matrix-v1',
      id: 'matrix',
      version: '1',
      cases: cases,
    )
  end

  def attack_case(id: 'case-1', family: :paraphrase, access: :black_box,
                  attack_budget: 12)
    {
      id: id,
      parent_case_id: 'workspace/user_task_0/injection_task_0',
      family: family,
      split: :test,
      language: :en,
      domain: :workspace,
      origin: :tool,
      access: access,
      attack_budget: attack_budget,
      seed: 5,
      utility_constraint: { baseline_required: true, preserve_task: true },
      scenario: { suite: 'workspace', user_task_id: 'user_task_0' },
    }
  end

  def response(case_id, security_success:, utility_under_attack:, queries:)
    {
      schema: 'vangrail-adaptive-response-v1',
      case_id: case_id,
      target_id: 'target-v1',
      adversary: { id: 'search-v1', version: '1.0.0', access: 'black_box' },
      status: 'ok',
      utility_without_attack: true,
      utility_under_attack: utility_under_attack,
      security_success: security_success,
      attack_success: !security_success,
      score: security_success ? 0.2 : 0.9,
      queries: queries,
      model_calls: queries,
      tool_calls: 1,
      duration_seconds: 0.5,
      trace_sha256: TRACE_SHA,
    }
  end

  def assert_request(request)
    assert_equal 'vangrail-adaptive-request-v1', request['schema']
    assert_equal 'adaptive-campaign-v1', request.dig('matrix', 'id')
    assert_equal 'target-v1', request.dig('target', 'id')
    assert_equal 41, request['seed']
  end

  def assert_success(row)
    assert_equal 'rewrite-1', row['case_id']
    assert_equal 'paraphrase', row['family']
    assert_equal 'black_box', row['access']
    assert_equal 'ok', row['status']
    refute row['security_success']
    assert row['attack_success']
    assert row['utility_without_attack']
    assert row['utility_under_attack']
    refute row['secure_utility']
    assert_equal 7, row['queries']
    assert_equal TRACE_SHA, row['trace_sha256']
  end
end
