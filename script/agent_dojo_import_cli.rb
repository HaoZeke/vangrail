# frozen_string_literal: true

require 'json'
require 'optparse'
require 'tempfile'
require_relative '../lib/vangrail/agent_dojo_adapter'

module Vangrail
  # Atomic importer for the pinned AgentDojo trace schema.
  class AgentDojoImportCli
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

      run = AgentDojoAdapter.new.import(
        options.fetch(:logdir),
        model_id: options.fetch(:model_id),
        defense: options.fetch(:defense),
        seed: options.fetch(:seed),
      )
      atomic_write(options.fetch(:output), JSON.pretty_generate(run.to_h) << "\n")
      0
    rescue OptionParser::ParseError, ProtocolError, ArgumentError,
           Errno::ENOENT, Errno::EACCES, IOError => e
      @stderr.puts("import_agentdojo: #{e.message}")
      1
    end

    private

    def parse_options(argv)
      values = {}
      parser = OptionParser.new do |options|
        options.banner = 'Usage: import_agentdojo.rb --logdir PATH --output PATH ' \
                         '--model-id ID --defense ID --seed INTEGER'
        options.on('--logdir PATH') { |path| values[:logdir] = path }
        options.on('--output PATH') { |path| values[:output] = path }
        options.on('--model-id ID') { |id| values[:model_id] = id }
        options.on('--defense ID') { |id| values[:defense] = id }
        options.on('--seed INTEGER', Integer) { |seed| values[:seed] = seed }
        options.on('-h', '--help') do
          @stdout.puts(options)
          values[:help] = true
        end
      end
      parser.parse!(argv)
      return nil if values.delete(:help)

      required = %i[logdir output model_id defense seed]
      missing = required.reject { |name| values.key?(name) }
      raise OptionParser::MissingArgument, missing.join(', ') unless missing.empty?

      values[:logdir] = File.expand_path(values[:logdir])
      values[:output] = File.expand_path(values[:output])
      values.freeze
    end

    def atomic_write(path, bytes)
      raise ProtocolError, "output already exists: #{path}" if File.exist?(path)
      unless Dir.exist?(File.dirname(path))
        raise ProtocolError,
              "output directory does not exist: #{File.dirname(path)}"
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
