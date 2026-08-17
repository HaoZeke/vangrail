# frozen_string_literal: true

require 'json'
require 'optparse'
require_relative 'builder'
require_relative 'errors'
require_relative 'front'
require_relative 'server'
require_relative 'version'

module Vangrail
  # JSON on stdin, JSON on stdout. The HTTP server is the same envelope.
  class CLI
    USAGE = <<~TEXT
      vangrail #{VERSION}

      vangrail check-input [--text STRING]
      vangrail check-output [--text STRING]
      vangrail check-context [--text STRING]
      vangrail screen
      vangrail assess [--text STRING] --prior FLOAT [--side input|context|output]
      vangrail serve [--bind HOST] [--port N]
    TEXT

    def self.run(argv, stdin: $stdin, stdout: $stdout, stderr: $stderr, env: ENV)
      new(argv, stdin: stdin, stdout: stdout, stderr: stderr, env: env).run
    end

    def initialize(argv, stdin:, stdout:, stderr:, env:)
      @argv = argv.dup
      @stdin = stdin
      @stdout = stdout
      @stderr = stderr
      @env = env
    end

    def run
      command = @argv.shift
      return usage(0) if command.nil? || %w[-h --help help].include?(command)
      return version if %w[-v --version version].include?(command)
      return serve if command == 'serve'

      name = command.to_s.tr('-', '_')
      return fail_usage("unknown command #{command}") unless Front::COMMANDS.include?(name)

      payload = front.dispatch(name, payload_for)
      write(payload)
      exit_status(payload)
    rescue ArgumentError, Error => e
      @stderr.puts(e.message)
      1
    rescue JSON::ParserError => e
      @stderr.puts("invalid JSON: #{e.message}")
      1
    end

    private

    def front
      @front ||= Front.new(engine: Builder.new(@env).engine)
    end

    def payload_for
      options, rest = parse_flags
      raise ArgumentError, "unexpected arguments: #{rest.join(' ')}" unless rest.empty?

      body = stdin_json.merge(options)
      body['text'] = options['text'] if options.key?('text')
      body
    end

    def parse_flags
      options = {}
      parser = OptionParser.new do |opts|
        opts.on('--text STRING', 'text to check') { |value| options['text'] = value }
        opts.on('--prior FLOAT', Float, 'required by assess') { |value| options['prior'] = value }
        opts.on('--side SIDE', 'input, context, or output') { |value| options['side'] = value }
      end
      rest = parser.parse(@argv)
      [options, rest]
    end

    def stdin_json
      raw = @stdin.tty? ? '' : @stdin.read
      raw.to_s.strip.empty? ? {} : JSON.parse(raw)
    end

    def serve
      bind = '127.0.0.1'
      port = 9292
      parser = OptionParser.new do |opts|
        opts.on('--bind HOST', 'listen address') { |value| bind = value }
        opts.on('--port N', Integer, 'listen port') { |value| port = value }
      end
      parser.parse(@argv)
      server = Server.new(front: front, host: bind, port: port)
      @stdout.puts(JSON.generate('ok' => true, 'base_url' => server.base_url, 'version' => VERSION))
      server.start
      sleep
      0
    rescue Interrupt
      0
    end

    def write(payload)
      @stdout.puts(JSON.generate(payload))
    end

    # 0 is a certain allow. 2 is a block. 3 is an uncertain allow. A shell
    # that only reads the process status must not treat a blocked or unchecked
    # verdict as success.
    def exit_status(payload)
      return 2 if payload['status'] == 'blocked'
      return 3 if payload['certain'] == false

      0
    end

    def version
      @stdout.puts(VERSION)
      0
    end

    def usage(code)
      stream = code.zero? ? @stdout : @stderr
      stream.write(USAGE)
      code
    end

    def fail_usage(message)
      @stderr.puts(message)
      usage(1)
    end
  end
end
