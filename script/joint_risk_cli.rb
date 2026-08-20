# frozen_string_literal: true

require 'digest'
require 'fileutils'
require 'json'
require 'optparse'
require 'tempfile'
require_relative 'joint_risk_training'

module Vangrail
  # Bounded command-line materialization of a joint-risk training package.
  class JointRiskTrainingCli
    MAX_CASE_BYTES = 64 * 1024 * 1024
    MAX_LINE_BYTES = 1024 * 1024
    MAX_CONFIG_BYTES = 1024 * 1024
    OUTPUT_NAMES = %i[artifact report model_card manifest].freeze
    TRAINING_KEYS = %w[
      id readers normalization calibration_valid_until max_false_positive_rate interactions
      disagreement_pairs risk_confidence iterations ridge
    ].freeze

    def self.run(argv, stdout: $stdout, stderr: $stderr)
      new(stdout: stdout, stderr: stderr).run(argv)
    end

    def initialize(stdout:, stderr:)
      @stdout = stdout
      @stderr = stderr
    end

    def run(argv)
      paths = parse_options(argv)
      return 0 unless paths

      raw_cases = bounded_read(paths.fetch(:cases), MAX_CASE_BYTES, 'cases')
      raw_config = bounded_read(paths.fetch(:config), MAX_CONFIG_BYTES, 'config')
      cases = parse_cases(raw_cases)
      config = parse_config(raw_config)
      artifact, report = JointRiskTraining.fit(cases, **training_options(config))
      write_package(paths, raw_cases, raw_config, cases, config, artifact, report)
      0
    rescue OptionParser::ParseError, JSON::ParserError, ProtocolError, ArgumentError,
           Errno::ENOENT, Errno::EACCES, IOError => e
      @stderr.puts("train_joint_risk: #{e.message}")
      1
    end

    private

    def parse_options(argv)
      paths = {}
      parser = OptionParser.new do |options|
        options.banner = 'Usage: train_joint_risk.rb --cases PATH --config PATH --artifact PATH ' \
                         '--report PATH --model-card PATH --manifest PATH'
        options.on('--cases PATH') { |path| paths[:cases] = path }
        options.on('--config PATH') { |path| paths[:config] = path }
        options.on('--artifact PATH') { |path| paths[:artifact] = path }
        options.on('--report PATH') { |path| paths[:report] = path }
        options.on('--model-card PATH') { |path| paths[:model_card] = path }
        options.on('--manifest PATH') { |path| paths[:manifest] = path }
        options.on('-h', '--help') do
          @stdout.puts(options)
          return nil
        end
      end
      parser.parse!(argv)
      required = %i[cases config] + OUTPUT_NAMES
      missing = required.reject { |name| paths.key?(name) }
      raise OptionParser::MissingArgument, missing.join(', ') unless missing.empty?
      unless paths.values_at(*OUTPUT_NAMES).uniq.size == 4
        raise OptionParser::InvalidArgument,
              'output paths must be distinct'
      end

      paths.transform_values { |path| File.expand_path(path) }.freeze
    end

    def bounded_read(path, maximum, name)
      size = File.size(path)
      raise ProtocolError, "#{name} input exceeds #{maximum} bytes" if size > maximum

      File.binread(path)
    end

    def parse_cases(bytes)
      cases = []
      bytes.each_line.with_index(1) do |line, number|
        raise ProtocolError, "case line #{number} exceeds #{MAX_LINE_BYTES} bytes" if line.bytesize > MAX_LINE_BYTES
        next if line.strip.empty?

        value = JSON.parse(line)
        raise ProtocolError, "case line #{number} must contain a JSON object" unless value.is_a?(Hash)

        cases << value
      rescue JSON::ParserError => e
        raise ProtocolError, "case line #{number} is invalid JSON: #{e.message}"
      end
      raise ProtocolError, 'cases input is empty' if cases.empty?

      cases.freeze
    end

    def parse_config(bytes)
      config = JSON.parse(bytes)
      raise ProtocolError, 'training config must be a JSON object' unless config.is_a?(Hash)

      unknown = config.keys - TRAINING_KEYS - ['model_card']
      raise ProtocolError, "unknown training config fields: #{unknown.join(', ')}" unless unknown.empty?

      config
    end

    def training_options(config)
      TRAINING_KEYS.each_with_object({}) do |name, options|
        options[name.to_sym] = config[name] if config.key?(name)
      end
    end

    def write_package(paths, raw_cases, raw_config, cases, config, artifact, report)
      artifact_bytes = pretty_json(artifact.data)
      report_bytes = pretty_json(report)
      artifact_file_sha = digest(artifact_bytes)
      card = model_card(config, artifact, report, artifact_file_sha)
      card_bytes = pretty_json(card)
      manifest = manifest(
        raw_cases,
        raw_config,
        cases,
        report,
        artifact_bytes,
        report_bytes,
        card_bytes,
      )
      atomic_write(
        paths.fetch(:artifact) => artifact_bytes,
        paths.fetch(:report) => report_bytes,
        paths.fetch(:model_card) => card_bytes,
        paths.fetch(:manifest) => pretty_json(manifest),
      )
    end

    def model_card(config, artifact, report, artifact_file_sha)
      metadata = config.fetch('model_card', {})
      raise ProtocolError, 'model_card config must be a JSON object' unless metadata.is_a?(Hash)

      {
        'schema' => 'vangrail-joint-risk-model-card-v1',
        'artifact_id' => artifact.id,
        'artifact_schema' => JointRiskArtifact::SCHEMA,
        'artifact_sha256' => artifact.sha256,
        'artifact_file_sha256' => artifact_file_sha,
        'posterior_method' => artifact.posterior_method,
        'reader_identities' => artifact.readers,
        'normalization' => artifact.normalization,
        'training_prevalence' => artifact.training_prevalence,
        'training_threat_composition' => artifact.threat_model.fetch('training_composition'),
        'calibration' => artifact.calibration,
        'risk_control' => artifact.risk_control,
        'ood' => artifact.ood,
        'supported' => artifact.supported,
        'role_counts' => report.fetch('role_counts'),
        'test_metrics' => report.fetch('test'),
        'distribution' => metadata.fetch('distribution', 'unspecified'),
        'assumptions' => Array(metadata['assumptions']).map(&:to_s),
        'claim_boundary' => 'Empirical risk control applies only to the named threshold distribution.',
      }
    end

    def manifest(raw_cases, raw_config, cases, report, artifact_bytes, report_bytes, card_bytes)
      {
        'schema' => 'vangrail-joint-risk-training-manifest-v1',
        'inputs' => {
          'cases' => { 'sha256' => digest(raw_cases), 'bytes' => raw_cases.bytesize },
          'config' => { 'sha256' => digest(raw_config), 'bytes' => raw_config.bytesize },
        },
        'outputs' => {
          'artifact' => output_digest(artifact_bytes),
          'report' => output_digest(report_bytes),
          'model_card' => output_digest(card_bytes),
        },
        'role_counts' => report.fetch('role_counts'),
        'splits' => split_manifest(cases),
      }
    end

    def split_manifest(cases)
      cases.group_by { |row| fetch(row, 'role').to_s }
           .sort.to_h do |role, rows|
        [
          role,
          {
            'case_ids' => rows.map { |row| fetch(row, 'id').to_s }.sort,
            'groups' => rows.map { |row| fetch(row, 'group').to_s }.uniq.sort,
          },
        ]
      end
    end

    def output_digest(bytes)
      { 'sha256' => digest(bytes), 'bytes' => bytes.bytesize }
    end

    def pretty_json(value)
      JSON.pretty_generate(value) << "\n"
    end

    def digest(bytes)
      Digest::SHA256.hexdigest(bytes)
    end

    def fetch(hash, name)
      hash.key?(name) ? hash.fetch(name) : hash.fetch(name.to_sym)
    end

    def atomic_write(payloads)
      payloads.each_key do |path|
        raise ProtocolError, "output already exists: #{path}" if File.exist?(path)
        unless Dir.exist?(File.dirname(path))
          raise ProtocolError,
                "output directory does not exist: #{File.dirname(path)}"
        end
      end

      staged = payloads.to_h { |path, bytes| [path, stage(path, bytes)] }
      published = []
      staged.each do |path, temporary|
        temporary.close
        File.rename(temporary.path, path)
        published << path
      end
    rescue StandardError
      published&.each { |path| FileUtils.rm_f(path) }
      raise
    ensure
      staged&.each_value(&:close!)
    end

    def stage(path, bytes)
      temporary = Tempfile.new([".#{File.basename(path)}", '.tmp'], File.dirname(path))
      temporary.binmode
      temporary.write(bytes)
      temporary.flush
      temporary.fsync
      temporary
    end
  end
end
