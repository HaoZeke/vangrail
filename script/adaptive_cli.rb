# frozen_string_literal: true

require 'json'
require 'optparse'
require 'tempfile'
require_relative '../lib/vangrail/adaptive_benchmark'

module Vangrail
  # Executes a checksum-pinned matrix through an optional external adversary.
  class AdaptiveCli
    MAX_TARGET_BYTES = 1024 * 1024

    def self.run(argv, stdout: $stdout, stderr: $stderr)
      new(stdout: stdout, stderr: stderr).run(argv)
    end

    def initialize(stdout:, stderr:)
      @stdout = stdout
      @stderr = stderr
    end

    def run(argv)
      options, command = parse_options(argv)
      return 0 unless options

      matrix = AdaptiveAttackMatrix.load(
        options.fetch(:matrix),
        expected_sha256: options.fetch(:matrix_sha256),
      )
      target = parse_target(options.fetch(:target))
      runner = AdaptiveRunners::Command.new(
        command: command,
        timeout: options.fetch(:timeout),
      )
      result = AdaptiveBenchmarkAdapter.new(matrix: matrix, runner: runner)
                                       .run(target: target, seed: options.fetch(:seed))
      atomic_write(options.fetch(:output), JSON.pretty_generate(result.to_h) << "\n")
      0
    rescue OptionParser::ParseError, ProtocolError, ArgumentError,
           Errno::ENOENT, Errno::EACCES, IOError => e
      @stderr.puts("run_adaptive: #{e.message}")
      1
    end

    private

    def parse_options(argv)
      values = { timeout: AdaptiveRunners::Command::DEFAULT_TIMEOUT }
      parser = option_parser(values)
      parser.parse!(argv)
      return [nil, []] if values.delete(:help)

      required = %i[matrix matrix_sha256 target output seed]
      missing = required.reject { |name| values.key?(name) }
      raise OptionParser::MissingArgument, missing.join(', ') unless missing.empty?
      raise OptionParser::MissingArgument, 'runner command after --' if argv.empty?

      %i[matrix target output].each { |name| values[name] = File.expand_path(values[name]) }
      [values.freeze, argv.map(&:to_s).freeze]
    end

    def option_parser(values)
      OptionParser.new do |options|
        options.banner = 'Usage: run_adaptive.rb --matrix PATH --matrix-sha256 SHA256 ' \
                         '--target PATH --output PATH --seed INTEGER -- COMMAND [ARG...]'
        options.on('--matrix PATH') { |path| values[:matrix] = path }
        options.on('--matrix-sha256 SHA256') { |digest| values[:matrix_sha256] = digest }
        options.on('--target PATH') { |path| values[:target] = path }
        options.on('--output PATH') { |path| values[:output] = path }
        options.on('--seed INTEGER', Integer) { |seed| values[:seed] = seed }
        options.on('--timeout SECONDS', Float) { |seconds| values[:timeout] = seconds }
        options.on('-h', '--help') do
          @stdout.puts(options)
          values[:help] = true
        end
      end
    end

    def parse_target(path)
      size = File.size(path)
      raise ProtocolError, "target input exceeds #{MAX_TARGET_BYTES} bytes" if size > MAX_TARGET_BYTES

      value = JSON.parse(File.binread(path))
      raise ProtocolError, 'target must be a JSON object' unless value.is_a?(Hash)

      value
    rescue JSON::ParserError => e
      raise ProtocolError, "target is invalid JSON: #{e.message}"
    end

    def atomic_write(path, bytes)
      raise ProtocolError, "output already exists: #{path}" if File.exist?(path)
      unless Dir.exist?(File.dirname(path))
        raise ProtocolError, "output directory does not exist: #{File.dirname(path)}"
      end

      temporary = Tempfile.new([".#{File.basename(path)}", '.tmp'], File.dirname(path))
      temporary.binmode
      temporary.write(bytes)
      temporary.flush
      temporary.fsync
      temporary.close
      File.rename(temporary.path, path)
    ensure
      temporary&.close!
    end
  end
end
