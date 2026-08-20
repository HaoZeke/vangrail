# frozen_string_literal: true

require 'digest'
require 'json'
require_relative 'benchmark_run'

module Vangrail
  # Imports a pinned AgentDojo trace tree without loading its Python package.
  class AgentDojoAdapter
    PACKAGE_VERSION = '0.1.35'
    PACKAGE_SHA256 = '9eacbc89d996f8656b235ad7b626bcf840b1ace7101174ca62d790c7c6d62956'
    BENCHMARK_VERSION = 'v1.2.2'
    ADAPTER_SCHEMA = 'agentdojo-traces-v0.1.35'
    MAX_TRACE_BYTES = 16 * 1024 * 1024
    MAX_TRACES = 100_000
    BOOLEAN_VALUES = [true, false].freeze
    REQUIRED_FIELDS = %w[
      suite_name pipeline_name user_task_id injection_task_id attack_type injections messages
      error benchmark_version agentdojo_package_version duration utility security
    ].freeze

    Trace = Struct.new(:data, :path, :sha256, keyword_init: true)

    attr_reader :package_version, :package_sha256, :benchmark_version

    def initialize(package_version: PACKAGE_VERSION, package_sha256: PACKAGE_SHA256,
                   benchmark_version: BENCHMARK_VERSION)
      @package_version = required_string(package_version, 'package version')
      @package_sha256 = required_digest(package_sha256, 'package SHA-256')
      @benchmark_version = required_string(benchmark_version, 'benchmark version')
      freeze
    end

    def import(logdir, model_id:, defense:, seed:)
      traces, source = load_traces(logdir)
      validate_versions!(traces)
      attacked = traces.select { |trace| trace.data['attack_type'] }
      attack = one_value!(attacked, 'attack_type', 'one attack')
      pipeline = one_value!(attacked, 'pipeline_name', 'one pipeline')
      baselines = baseline_index(traces, pipeline)
      cases = attacked.map { |trace| case_from(trace, baselines) }.sort_by { |row| row['case_id'] }

      BenchmarkRun.new(
        'schema' => BenchmarkRun::SCHEMA,
        'adapter' => { 'id' => ADAPTER_SCHEMA },
        'benchmark' => benchmark_identity,
        'target' => target_identity(pipeline, model_id, defense),
        'attack' => { 'name' => attack },
        'seed' => integer(seed, 'seed'),
        'source' => source,
        'cases' => cases,
        'status_counts' => status_counts(cases),
        'denominator' => cases.size,
      )
    end

    def command(python:, logdir:, model:, attack:, defense: nil, model_id: nil,
                suites: [], user_tasks: [], injection_tasks: [], modules: [],
                max_workers: 1, force_rerun: false)
      argv = [
        required_string(python, 'Python executable'), '-m', 'agentdojo.scripts.benchmark',
        '--benchmark-version', benchmark_version,
        '--logdir', required_string(logdir, 'log directory'),
        '--model', required_string(model, 'model')
      ]
      argv.push('--model-id', model_id.to_s) if model_id
      argv.push('--attack', attack.to_s) if attack
      argv.push('--defense', defense.to_s) if defense
      argv.push('--max-workers', positive_integer(max_workers, 'max workers').to_s)
      argv << '--force-rerun' if force_rerun
      append_each(argv, '-s', suites)
      append_each(argv, '-ut', user_tasks)
      append_each(argv, '-it', injection_tasks)
      append_each(argv, '-ml', modules)
      argv
    end

    private

    def load_traces(logdir)
      root = File.realpath(logdir)
      paths = Dir.glob(File.join(root, '**', '*.json'))
      raise ArtifactError, 'AgentDojo trace tree is empty' if paths.empty?
      raise ArtifactError, "AgentDojo trace tree exceeds #{MAX_TRACES} files" if paths.size > MAX_TRACES

      files = paths.map { |path| source_file(root, path) }
      traces = files.map { |row| parse_trace(root, row) }
      source = {
        'schema' => 'sha256-tree-v1',
        'sha256' => Digest::SHA256.hexdigest(JSON.generate(files)),
        'files' => files,
      }
      [traces, source]
    rescue Errno::ENOENT, Errno::ENOTDIR => e
      raise ArtifactError, "AgentDojo trace tree is unavailable: #{e.message}"
    end

    def source_file(root, path)
      real = File.realpath(path)
      unless real.start_with?("#{root}/") && File.file?(real)
        raise ArtifactError, "AgentDojo trace escapes its source tree: #{path}"
      end

      size = File.size(real)
      raise ArtifactError, "AgentDojo trace exceeds #{MAX_TRACE_BYTES} bytes: #{path}" if size > MAX_TRACE_BYTES

      {
        'path' => real.delete_prefix("#{root}/"),
        'sha256' => Digest::SHA256.file(real).hexdigest,
        'bytes' => size,
      }
    end

    def parse_trace(root, source)
      path = File.join(root, source['path'])
      data = JSON.parse(File.binread(path))
      validate_trace!(data, source['path'])
      Trace.new(data: data, path: source['path'], sha256: source['sha256']).freeze
    rescue JSON::ParserError => e
      raise ArtifactError, "AgentDojo trace is not JSON at #{source['path']}: #{e.message}"
    end

    def validate_trace!(data, path)
      raise ArtifactError, "AgentDojo trace must be an object at #{path}" unless data.is_a?(Hash)

      missing = REQUIRED_FIELDS - data.keys
      raise ArtifactError, "AgentDojo trace is missing #{missing.join(', ')} at #{path}" unless missing.empty?

      %w[suite_name pipeline_name user_task_id benchmark_version agentdojo_package_version].each do |field|
        required_string(data[field], "#{field} at #{path}")
      end
      %w[utility security].each do |field|
        next if BOOLEAN_VALUES.include?(data[field])

        raise ArtifactError, "#{field} must be boolean at #{path}"
      end
      raise ArtifactError, "messages must be an array at #{path}" unless data['messages'].is_a?(Array)
      raise ArtifactError, "injections must be an object at #{path}" unless data['injections'].is_a?(Hash)

      finite_nonnegative(data['duration'], "duration at #{path}")
    end

    def validate_versions!(traces)
      packages = traces.map { |trace| trace.data['agentdojo_package_version'] }.uniq
      unless packages == [package_version]
        raise ArtifactError, "AgentDojo package version #{packages.join(', ')} does not match #{package_version}"
      end

      versions = traces.map { |trace| trace.data['benchmark_version'] }.uniq
      return if versions == [benchmark_version]

      raise ArtifactError, "AgentDojo benchmark version #{versions.join(', ')} does not match #{benchmark_version}"
    end

    def one_value!(traces, field, description)
      values = traces.map { |trace| trace.data[field] }.uniq
      return values.first if values.size == 1 && !values.first.to_s.empty?

      raise ArtifactError, "AgentDojo trace tree must contain #{description}; found #{values.inspect}"
    end

    def baseline_index(traces, pipeline)
      traces.each_with_object({}) do |trace, index|
        data = trace.data
        next unless data['pipeline_name'] == pipeline && data['attack_type'].nil? && data['injection_task_id'].nil?

        key = [data['suite_name'], data['user_task_id']]
        raise ArtifactError, "duplicate AgentDojo baseline for #{key.join('/')}" if index.key?(key)

        index[key] = trace
      end
    end

    def case_from(trace, baselines)
      data = trace.data
      parent = [data['suite_name'], data['user_task_id']]
      baseline = baselines[parent]
      raise ArtifactError, "missing AgentDojo baseline for #{parent.join('/')}" unless baseline

      attack_error = data['error']
      baseline_error = baseline.data['error']
      status = attack_error || baseline_error ? 'error' : 'ok'
      security = status == 'ok' && data['security']
      {
        'case_id' => (parent + [required_string(data['injection_task_id'], 'injection task')]).join('/'),
        'parent_case_id' => parent.join('/'),
        'suite' => data['suite_name'],
        'user_task_id' => data['user_task_id'],
        'injection_task_id' => data['injection_task_id'],
        'status' => status,
        'baseline_status' => baseline_error ? 'error' : 'ok',
        'attack_status' => attack_error ? 'error' : 'ok',
        'error' => attack_error || baseline_error,
        'utility_without_attack' => baseline.data['utility'],
        'utility_under_attack' => data['utility'],
        'reported_security' => data['security'],
        'security_success' => security,
        'attack_success' => status == 'ok' && !data['security'],
        'secure_utility' => security && baseline.data['utility'] && data['utility'],
        'duration_seconds' => data['duration'],
        'baseline_duration_seconds' => baseline.data['duration'],
        'trace_sha256' => trace.sha256,
        'baseline_trace_sha256' => baseline.sha256,
      }
    end

    def benchmark_identity
      {
        'name' => 'agentdojo',
        'version' => benchmark_version,
        'package_version' => package_version,
        'package_sha256' => package_sha256,
      }
    end

    def target_identity(pipeline, model_id, defense)
      {
        'pipeline_name' => pipeline,
        'model_id' => required_string(model_id, 'model id'),
        'defense' => required_string(defense, 'defense'),
      }
    end

    def status_counts(cases)
      BenchmarkRun::STATUSES.to_h { |status| [status, cases.count { |row| row['status'] == status }] }
    end

    def append_each(argv, flag, values)
      Array(values).each { |value| argv.push(flag, required_string(value, flag)) }
    end

    def required_string(value, name)
      text = value.to_s
      return text if (value.is_a?(String) || value.is_a?(Symbol)) && !text.empty?

      raise ArtifactError, "#{name} is required"
    end

    def required_digest(value, name)
      digest = value.to_s
      return digest if digest.match?(/\A[0-9a-f]{64}\z/)

      raise ArtifactError, "#{name} must be a lowercase SHA-256 digest"
    end

    def integer(value, name)
      return value if value.is_a?(Integer)

      raise ArtifactError, "#{name} must be an integer"
    end

    def positive_integer(value, name)
      number = integer(value, name)
      return number if number.positive?

      raise ArtifactError, "#{name} must be positive"
    end

    def finite_nonnegative(value, name)
      return value if value.is_a?(Numeric) && value.finite? && !value.negative?

      raise ArtifactError, "#{name} must be finite and nonnegative"
    end
  end
end
