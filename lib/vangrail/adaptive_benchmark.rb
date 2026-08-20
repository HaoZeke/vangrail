# frozen_string_literal: true

require_relative 'adaptive_attack_matrix'
require_relative 'benchmark_run'
require_relative 'bounded_json_command'

module Vangrail
  # Dependency-free transports for optional adaptive adversaries.
  module AdaptiveRunners
    REQUEST_SCHEMA = 'vangrail-adaptive-request-v1'
    RESPONSE_SCHEMA = 'vangrail-adaptive-response-v1'

    # One bounded JSON request on stdin and one response on stdout.
    class Command
      DEFAULT_TIMEOUT = 300
      DEFAULT_MAX_INPUT_BYTES = 4 * 1024 * 1024
      DEFAULT_MAX_OUTPUT_BYTES = 16 * 1024 * 1024

      def initialize(command:, timeout: DEFAULT_TIMEOUT,
                     max_input_bytes: DEFAULT_MAX_INPUT_BYTES,
                     max_output_bytes: DEFAULT_MAX_OUTPUT_BYTES,
                     environment: {}, inherit_environment: false)
        @transport = BoundedJsonCommand.new(
          command: command,
          timeout: timeout,
          max_input_bytes: max_input_bytes,
          max_output_bytes: max_output_bytes,
          environment: environment,
          inherit_environment: inherit_environment,
          label: 'adaptive runner',
        )
      end

      def run(request)
        @transport.call(request)
      end
    end
  end

  # Executes a matrix against a target through a versioned optional runner.
  class AdaptiveBenchmarkAdapter
    include ArtifactData

    TARGET_FIELDS = %w[id model_id environment_id defense].freeze
    RESPONSE_FIELDS = %w[
      schema case_id target_id adversary status reason utility_without_attack utility_under_attack
      security_success attack_success score queries model_calls tool_calls duration_seconds trace_sha256
    ].freeze
    SUCCESS_FIELDS = %w[
      utility_without_attack utility_under_attack security_success attack_success score
    ].freeze
    DIGEST = /\A[0-9a-f]{64}\z/

    attr_reader :matrix, :runner

    def initialize(matrix:, runner:)
      raise ArgumentError, 'matrix must be an AdaptiveAttackMatrix' unless matrix.is_a?(AdaptiveAttackMatrix)
      raise ArgumentError, 'runner must respond to run' unless runner.respond_to?(:run)

      @matrix = matrix
      @runner = runner
      freeze
    end

    def run(target:, seed:)
      normalized_target = normalize_target(target)
      run_seed = integer(seed, 'benchmark seed')
      cases = matrix.to_h.fetch('cases').map do |attack_case|
        execute_case(attack_case, normalized_target, run_seed)
      end.sort_by { |row| row['case_id'] }

      BenchmarkRun.new(
        'schema' => BenchmarkRun::SCHEMA,
        'adapter' => { 'id' => 'adaptive-runner-v1' },
        'benchmark' => { 'name' => 'adaptive-security', 'version' => matrix.version },
        'target' => normalized_target,
        'attack' => {
          'matrix_id' => matrix.id,
          'matrix_version' => matrix.version,
          'matrix_sha256' => matrix.sha256,
        },
        'seed' => run_seed,
        'source' => {
          'schema' => AdaptiveAttackMatrix::SCHEMA,
          'id' => matrix.id,
          'sha256' => matrix.sha256,
        },
        'cases' => cases,
        'status_counts' => status_counts(cases),
        'denominator' => cases.size,
      )
    end

    private

    def execute_case(attack_case, target, seed)
      request = {
        'schema' => AdaptiveRunners::REQUEST_SCHEMA,
        'matrix' => { 'id' => matrix.id, 'version' => matrix.version, 'sha256' => matrix.sha256 },
        'case' => attack_case,
        'target' => target,
        'seed' => seed,
      }
      response = stringify(runner.run(request))
      validate_response!(response, attack_case, target)
      result_row(attack_case, response)
    rescue Error => e
      error_row(attack_case, e.message)
    rescue StandardError => e
      error_row(attack_case, "runner failure: #{e.class}")
    end

    def validate_response!(response, attack_case, target)
      raise ArtifactError, 'adaptive response must be an object' unless response.is_a?(Hash)

      unknown = response.keys - RESPONSE_FIELDS
      raise ArtifactError, "unknown adaptive response fields: #{unknown.join(', ')}" unless unknown.empty?
      unless response['schema'] == AdaptiveRunners::RESPONSE_SCHEMA
        raise ArtifactError, "adaptive response schema must be #{AdaptiveRunners::RESPONSE_SCHEMA}"
      end
      unless response['case_id'] == attack_case['id'] && response['target_id'] == target['id']
        raise ArtifactError, 'adaptive response case identity does not match the request'
      end

      validate_common_response!(response, attack_case)
      response['status'] == 'ok' ? validate_success!(response) : validate_abstention!(response)
    end

    def validate_common_response!(response, attack_case)
      status = response['status']
      raise ArtifactError, 'adaptive response status must be ok or abstained' unless %w[ok abstained].include?(status)

      adversary = response['adversary']
      unless adversary.is_a?(Hash) && %w[id version access].all? { |field| !adversary[field].to_s.empty? }
        raise ArtifactError, 'adaptive response adversary identity is required'
      end
      unless adversary['access'] == attack_case['access']
        raise ArtifactError, 'adaptive response access does not match the attack case'
      end

      count!(response, 'queries', maximum: attack_case['attack_budget'])
      count!(response, 'model_calls')
      count!(response, 'tool_calls')
      finite_nonnegative!(response['duration_seconds'], 'adaptive response duration_seconds')
      unless response['trace_sha256'].to_s.match?(DIGEST)
        raise ArtifactError, 'adaptive response trace_sha256 must be a lowercase SHA-256 digest'
      end
    end

    def validate_success!(response)
      missing = SUCCESS_FIELDS.reject { |field| response.key?(field) }
      raise ArtifactError, "adaptive response is missing #{missing.join(', ')}" unless missing.empty?

      %w[utility_without_attack utility_under_attack security_success attack_success].each do |field|
        boolean!(response[field], "adaptive response #{field}")
      end
      unless response['attack_success'] == !response['security_success']
        raise ArtifactError, 'adaptive attack and security outcomes must be complements'
      end
      probability!(response['score'], 'adaptive response score')
    end

    def validate_abstention!(response)
      return unless response['reason'].to_s.empty?

      raise ArtifactError, 'adaptive abstention reason is required'
    end

    def result_row(attack_case, response)
      return abstained_row(attack_case, response) if response['status'] == 'abstained'

      security = response['security_success']
      row_identity(attack_case).merge(
        'status' => 'ok',
        'error' => nil,
        'utility_without_attack' => response['utility_without_attack'],
        'utility_under_attack' => response['utility_under_attack'],
        'security_success' => security,
        'attack_success' => response['attack_success'],
        'secure_utility' => security && response['utility_without_attack'] && response['utility_under_attack'],
        'score' => response['score'],
        'queries' => response['queries'],
        'model_calls' => response['model_calls'],
        'tool_calls' => response['tool_calls'],
        'duration_seconds' => response['duration_seconds'],
        'trace_sha256' => response['trace_sha256'],
        'adversary' => response['adversary'],
      )
    end

    def abstained_row(attack_case, response)
      row_identity(attack_case).merge(
        'status' => 'abstained',
        'error' => response['reason'],
        'utility_without_attack' => false,
        'utility_under_attack' => false,
        'security_success' => false,
        'attack_success' => false,
        'secure_utility' => false,
        'score' => nil,
        'queries' => response['queries'],
        'model_calls' => response['model_calls'],
        'tool_calls' => response['tool_calls'],
        'duration_seconds' => response['duration_seconds'],
        'trace_sha256' => response['trace_sha256'],
        'adversary' => response['adversary'],
      )
    end

    def error_row(attack_case, message)
      row_identity(attack_case).merge(
        'status' => 'error',
        'error' => message.to_s,
        'utility_without_attack' => false,
        'utility_under_attack' => false,
        'security_success' => false,
        'attack_success' => false,
        'secure_utility' => false,
        'score' => nil,
        'queries' => 0,
        'model_calls' => 0,
        'tool_calls' => 0,
        'duration_seconds' => 0.0,
        'trace_sha256' => nil,
        'adversary' => nil,
      )
    end

    def row_identity(attack_case)
      {
        'case_id' => attack_case['id'],
        'parent_case_id' => attack_case['parent_case_id'],
        'family' => attack_case['family'],
        'split' => attack_case['split'],
        'language' => attack_case['language'],
        'domain' => attack_case['domain'],
        'origin' => attack_case['origin'],
        'access' => attack_case['access'],
        'attack_budget' => attack_case['attack_budget'],
        'case_seed' => attack_case['seed'],
      }
    end

    def normalize_target(raw)
      target = stringify(raw)
      unless target.is_a?(Hash) && (target.keys - TARGET_FIELDS).empty? &&
             TARGET_FIELDS.all? { |field| !target[field].to_s.empty? }
        raise ArtifactError, "target must name #{TARGET_FIELDS.join(', ')}"
      end

      target
    end

    def status_counts(cases)
      BenchmarkRun::STATUSES.to_h { |status| [status, cases.count { |row| row['status'] == status }] }
    end

    def count!(response, field, maximum: nil)
      value = response[field]
      unless value.is_a?(Integer) && !value.negative? && (!maximum || value <= maximum)
        raise ArtifactError, "adaptive response #{field} is outside its allowed range"
      end
    end

    def boolean!(value, name)
      return if value == true || value == false

      raise ArtifactError, "#{name} must be boolean"
    end

    def probability!(value, name)
      return if value.is_a?(Numeric) && value.finite? && value.between?(0.0, 1.0)

      raise ArtifactError, "#{name} must be a probability"
    end

    def finite_nonnegative!(value, name)
      return if value.is_a?(Numeric) && value.finite? && !value.negative?

      raise ArtifactError, "#{name} must be finite and nonnegative"
    end

    def integer(value, name)
      return value if value.is_a?(Integer)

      raise ArtifactError, "#{name} must be an integer"
    end
  end
end
