# frozen_string_literal: true

require 'fileutils'
require 'json'
require 'optparse'
require 'tempfile'

module Vangrail
  # Command-line materialization of raw and rendered performance reports.
  class RiskBenchmarkCli
    def self.run(argv, stdout: $stdout, stderr: $stderr)
      new(stdout: stdout, stderr: stderr).run(argv)
    end

    def initialize(stdout:, stderr:)
      @stdout = stdout
      @stderr = stderr
    end

    def run(argv)
      options, paths = parse_options(argv)
      report = RiskBenchmark.new(**options).run
      encoded = JSON.pretty_generate(report) << "\n"
      outputs = {}
      outputs[paths[:output]] = encoded if paths[:output]
      outputs[paths[:table]] = PerformanceReportTable.render(report) if paths[:table]
      atomic_write(outputs) unless outputs.empty?
      @stdout.print(encoded)
      0
    rescue OptionParser::ParseError, JSON::GeneratorError, ArgumentError,
           Errno::ENOENT, Errno::EACCES, IOError => e
      @stderr.puts("benchmark_risk: #{e.message}")
      1
    end

    private

    def parse_options(argv)
      values = {
        lengths: RiskBenchmark::DEFAULT_LENGTHS,
        samples: 9,
        iterations: 20,
        warmup: 5,
        buckets: LinearModel::BUCKETS,
        startup: true,
      }
      paths = {}
      option_parser(values, paths).parse!(argv)
      paths.transform_values! { |path| File.expand_path(path) }
      raise OptionParser::InvalidArgument, 'output paths must be distinct' if paths.values.uniq.size != paths.size

      [values.freeze, paths.freeze]
    end

    def option_parser(values, paths)
      OptionParser.new do |parser|
        parser.banner = 'Usage: ruby script/benchmark_risk.rb [options]'
        parser.on('--lengths LIST', 'comma-separated character lengths') do |value|
          values[:lengths] = value.split(',').map { |item| Integer(item, 10) }
        end
        parser.on('--samples N', Integer) { |value| values[:samples] = value }
        parser.on('--iterations N', Integer) { |value| values[:iterations] = value }
        parser.on('--warmup N', Integer) { |value| values[:warmup] = value }
        parser.on('--buckets N', Integer) { |value| values[:buckets] = value }
        parser.on('--[no-]startup', 'measure library startup in a subprocess') { |value| values[:startup] = value }
        parser.on('--output PATH', 'atomically write the JSON report') { |value| paths[:output] = value }
        parser.on('--table PATH', 'atomically write the Markdown table') { |value| paths[:table] = value }
      end
    end

    def atomic_write(payloads)
      payloads.each_key do |path|
        raise IOError, "output already exists: #{path}" if File.exist?(path)
        raise IOError, "output directory does not exist: #{File.dirname(path)}" unless Dir.exist?(File.dirname(path))
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
