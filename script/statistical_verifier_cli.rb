# frozen_string_literal: true

require 'digest'
require 'fileutils'
require 'json'
require 'optparse'
require 'tempfile'
require_relative '../lib/vangrail/statistical_verifier'
require_relative 'statistical_report_table'

module Vangrail
  # Bounded command-line verification and atomic report materialization.
  class StatisticalVerifierCli
    MAX_PREDICTION_BYTES = 64 * 1024 * 1024
    MAX_LINE_BYTES = 1024 * 1024
    MAX_METADATA_BYTES = 4 * 1024 * 1024
    OUTPUTS = %i[report table].freeze

    def self.run(argv, stdout: $stdout, stderr: $stderr)
      new(stdout: stdout, stderr: stderr).run(argv)
    end

    def initialize(stdout:, stderr:)
      @stdout = stdout
      @stderr = stderr
    end

    def run(argv)
      options = parse_options(argv)
      return 0 unless options

      inputs = read_inputs(options)
      report = verify(inputs, options)
      report = report.merge('inputs' => input_manifest(inputs))
      atomic_write(
        options.fetch(:report) => JSON.pretty_generate(report) << "\n",
        options.fetch(:table) => StatisticalReportTable.render(report),
      )
      0
    rescue OptionParser::ParseError, JSON::ParserError, ProtocolError, ArgumentError,
           Errno::ENOENT, Errno::EACCES, IOError => e
      @stderr.puts("verify_evaluation: #{e.message}")
      1
    end

    private

    def parse_options(argv)
      values = { bootstrap_seed: 1, bootstrap_replicates: 2_000 }
      parser = OptionParser.new do |options|
        options.banner = 'Usage: verify_evaluation.rb --predictions PATH --threshold PATH ' \
                         '--artifacts PATH --report PATH --table PATH'
        options.on('--predictions PATH') { |path| values[:predictions] = path }
        options.on('--threshold PATH') { |path| values[:threshold] = path }
        options.on('--artifacts PATH') { |path| values[:artifacts] = path }
        options.on('--report PATH') { |path| values[:report] = path }
        options.on('--table PATH') { |path| values[:table] = path }
        options.on('--bootstrap-seed INTEGER', Integer) { |seed| values[:bootstrap_seed] = seed }
        options.on('--bootstrap-replicates INTEGER', Integer) { |count| values[:bootstrap_replicates] = count }
        options.on('-h', '--help') do
          @stdout.puts(options)
          return nil
        end
      end
      parser.parse!(argv)
      required = %i[predictions threshold artifacts] + OUTPUTS
      missing = required.reject { |name| values.key?(name) }
      raise OptionParser::MissingArgument, missing.join(', ') unless missing.empty?
      unless values.values_at(*OUTPUTS).uniq.size == OUTPUTS.size
        raise OptionParser::InvalidArgument, 'output paths must be distinct'
      end

      required.each { |name| values[name] = File.expand_path(values[name]) }
      values.freeze
    end

    def read_inputs(options)
      {
        predictions: bounded_read(options.fetch(:predictions), MAX_PREDICTION_BYTES, 'predictions'),
        threshold: bounded_read(options.fetch(:threshold), MAX_METADATA_BYTES, 'threshold'),
        artifacts: bounded_read(options.fetch(:artifacts), MAX_METADATA_BYTES, 'artifacts'),
      }
    end

    def bounded_read(path, maximum, name)
      size = File.size(path)
      raise ProtocolError, "#{name} input exceeds #{maximum} bytes" if size > maximum

      File.binread(path)
    end

    def verify(inputs, options)
      predictions = parse_predictions(inputs.fetch(:predictions))
      threshold = parse_object(inputs.fetch(:threshold), 'threshold')
      manifest = parse_object(inputs.fetch(:artifacts), 'artifact manifest')
      unless manifest['schema'] == 'vangrail-artifact-manifest-v1' && manifest['artifacts'].is_a?(Array)
        raise ProtocolError, 'artifact manifest must use vangrail-artifact-manifest-v1'
      end

      artifacts = resolve_artifacts(manifest['artifacts'], options.fetch(:artifacts))
      StatisticalVerifier.new(
        predictions: predictions,
        threshold: threshold,
        artifacts: artifacts,
        bootstrap_seed: options.fetch(:bootstrap_seed),
        bootstrap_replicates: options.fetch(:bootstrap_replicates),
      ).verify
    end

    def parse_predictions(bytes)
      rows = []
      bytes.each_line.with_index(1) do |line, number|
        raise ProtocolError, "prediction line #{number} exceeds #{MAX_LINE_BYTES} bytes" if line.bytesize > MAX_LINE_BYTES
        next if line.strip.empty?

        row = JSON.parse(line)
        raise ProtocolError, "prediction line #{number} must be an object" unless row.is_a?(Hash)

        rows << row
      rescue JSON::ParserError => e
        raise ProtocolError, "prediction line #{number} is invalid JSON: #{e.message}"
      end
      raise ProtocolError, 'predictions input is empty' if rows.empty?

      rows
    end

    def parse_object(bytes, name)
      value = JSON.parse(bytes)
      raise ProtocolError, "#{name} must be a JSON object" unless value.is_a?(Hash)

      value
    end

    def resolve_artifacts(artifacts, manifest_path)
      base = File.dirname(manifest_path)
      artifacts.map do |artifact|
        raise ProtocolError, 'artifact entry must be a JSON object' unless artifact.is_a?(Hash)

        artifact.merge('path' => File.expand_path(artifact.fetch('path'), base))
      end
    end

    def input_manifest(inputs)
      inputs.sort.to_h do |name, bytes|
        [name.to_s, { 'sha256' => Digest::SHA256.hexdigest(bytes), 'bytes' => bytes.bytesize }]
      end
    end

    def atomic_write(payloads)
      payloads.each_key do |path|
        raise ProtocolError, "output already exists: #{path}" if File.exist?(path)
        raise ProtocolError, "output directory does not exist: #{File.dirname(path)}" unless Dir.exist?(File.dirname(path))
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
