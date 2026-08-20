# frozen_string_literal: true

require 'json'
require 'open3'
require 'timeout'
require_relative 'errors'

module Vangrail
  # Bounded JSON-over-stdin subprocess transport with no implicit shell or environment.
  class BoundedJsonCommand
    class OutputLimit < StandardError; end

    READ_CHUNK = 16 * 1024
    TERMINATION_GRACE = 0.1

    attr_reader :command, :timeout, :environment, :inherit_environment,
                :max_input_bytes, :max_output_bytes, :label

    def initialize(command:, timeout:, max_input_bytes:, max_output_bytes:,
                   environment: {}, inherit_environment: false, label: 'JSON command')
      @command = Array(command).map(&:to_s).freeze
      @timeout = positive_number(timeout, 'timeout')
      @max_input_bytes = positive_integer(max_input_bytes, 'max_input_bytes')
      @max_output_bytes = positive_integer(max_output_bytes, 'max_output_bytes')
      @environment = environment.to_h { |name, value| [name.to_s, value.to_s] }.freeze
      @inherit_environment = !!inherit_environment # rubocop:disable Style/DoubleNegation
      @label = label.to_s.freeze
      raise ArgumentError, 'command is required' if @command.empty? || @command.any?(&:empty?)
    end

    def call(payload)
      input = JSON.generate(payload)
      raise ProtocolError, "#{label} request exceeds #{max_input_bytes} bytes" if input.bytesize > max_input_bytes

      output, status = execute(input)
      raise ProtocolError, exit_reason(status) unless status.success?

      parsed = JSON.parse(output)
      raise ProtocolError, "#{label} response must be a JSON object" unless parsed.is_a?(Hash)

      parsed
    rescue JSON::GeneratorError, EncodingError => e
      raise ProtocolError, "#{label} request is not valid JSON: #{e.message}"
    rescue JSON::ParserError => e
      raise ProtocolError, "#{label} returned invalid JSON: #{e.message}"
    end

    private

    def execute(input)
      Open3.popen3(environment, *command, unsetenv_others: !inherit_environment) do |stdin, stdout, stderr, wait|
        run_process(input, stdin, stdout, stderr, wait)
      end
    rescue Errno::ENOENT
      raise ProtocolError, "#{label} executable not found: #{command.first}"
    end

    def run_process(input, stdin, stdout, stderr, wait)
      threads = [
        worker { write_input(stdin, input) },
        worker { read_bounded(stdout) },
        worker { read_bounded(stderr) },
      ]
      Timeout.timeout(timeout) do
        threads.first.value
        output = threads.fetch(1).value
        threads.fetch(2).value
        [output, wait.value]
      end
    rescue Timeout::Error
      terminate(wait)
      raise ProtocolError, "#{label} timed out after #{timeout} seconds"
    rescue OutputLimit
      terminate(wait)
      raise ProtocolError, "#{label} output exceeds #{max_output_bytes} bytes"
    ensure
      [stdin, stdout, stderr].each { |stream| close(stream) }
      threads&.each { |thread| finish(thread) }
    end

    def write_input(stdin, input)
      stdin.write(input)
    rescue Errno::EPIPE, IOError
      nil
    ensure
      close(stdin)
    end

    def worker(&block)
      Thread.new(&block).tap { |thread| thread.report_on_exception = false }
    end

    def read_bounded(stream)
      output = +''
      loop do
        remaining = max_output_bytes - output.bytesize
        raise OutputLimit if remaining.negative?

        output << stream.readpartial([READ_CHUNK, remaining + 1].min)
        raise OutputLimit if output.bytesize > max_output_bytes
      end
    rescue EOFError
      output
    end

    def terminate(wait)
      return unless wait.alive?

      signal('TERM', wait.pid)
      signal('KILL', wait.pid) unless wait.join(TERMINATION_GRACE)
      wait.value
    rescue Errno::ECHILD
      nil
    end

    def signal(name, process_id)
      Process.kill(name, process_id)
    rescue Errno::ESRCH
      nil
    end

    def finish(thread)
      return unless thread.alive?

      thread.join(TERMINATION_GRACE)
      thread.kill if thread.alive?
    end

    def close(stream)
      stream.close unless stream.closed?
    rescue IOError
      nil
    end

    def exit_reason(status)
      value = status.exitstatus || "signal #{status.termsig}"
      "#{label} exited with status #{value}"
    end

    def positive_integer(value, name)
      number = Integer(value)
      raise ArgumentError unless number.positive?

      number
    rescue ArgumentError, TypeError
      raise ArgumentError, "#{name} must be a positive integer"
    end

    def positive_number(value, name)
      number = Float(value)
      raise ArgumentError unless number.positive? && number.finite?

      number
    rescue ArgumentError, TypeError
      raise ArgumentError, "#{name} must be a positive finite number"
    end
  end
end
