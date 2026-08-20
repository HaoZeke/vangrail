# frozen_string_literal: true

require 'json'
require 'open3'
require 'timeout'
require_relative 'errors'

module Vangrail
  # Versioned, dependency-free transports for optional risk readers.
  module ScoreProviders
    REQUEST_SCHEMA = 'vangrail-score-request-v1'
    RESPONSE_SCHEMA = 'vangrail-score-response-v1'
    DEFAULT_TIMEOUT = 30
    DEFAULT_MAX_INPUT_BYTES = 4 * 1024 * 1024
    DEFAULT_MAX_OUTPUT_BYTES = 1024 * 1024

    module_function

    def request(reader_id:, model_id:, feature_schema:, text:, side:, context:)
      json_value(
        schema: REQUEST_SCHEMA,
        reader_id: reader_id,
        model_id: model_id,
        feature_schema: feature_schema,
        text: text.to_s,
        side: side.to_s,
        context: context,
      )
    end

    def response(raw)
      raise ProtocolError, 'score response must be a JSON object' unless raw.is_a?(Hash)

      normalized = json_value(raw)
      unless normalized['schema'] == RESPONSE_SCHEMA
        raise ProtocolError, "score response schema must be #{RESPONSE_SCHEMA}"
      end

      normalized.except('schema')
    end

    def json_value(value)
      case value
      when Hash
        value.to_h { |name, nested| [name.to_s, json_value(nested)] }
      when Array then value.map { |nested| json_value(nested) }
      when Symbol then value.to_s
      else value
      end
    end

    # Shared request and response bounds for every optional transport.
    class Transport
      attr_reader :reader_id, :model_id, :feature_schema,
                  :max_input_bytes, :max_output_bytes

      def initialize(reader_id:, model_id:, feature_schema:,
                     max_input_bytes: DEFAULT_MAX_INPUT_BYTES,
                     max_output_bytes: DEFAULT_MAX_OUTPUT_BYTES)
        @reader_id = reader_id.to_s.freeze
        @model_id = model_id.to_s.freeze
        @feature_schema = Array(feature_schema).map(&:to_s).freeze
        @max_input_bytes = positive_integer(max_input_bytes, 'max_input_bytes')
        @max_output_bytes = positive_integer(max_output_bytes, 'max_output_bytes')
        raise ArgumentError, 'feature_schema is required' if @feature_schema.empty?
      end

      private

      def request_payload(text, side, context)
        payload = ScoreProviders.request(
          reader_id: reader_id,
          model_id: model_id,
          feature_schema: feature_schema,
          text: text,
          side: side,
          context: context,
        )
        bytes = generate(payload, 'score request')
        raise ProtocolError, "score request exceeds #{max_input_bytes} bytes" if bytes.bytesize > max_input_bytes

        [payload, bytes]
      end

      def response_payload(raw)
        bytes = generate(raw, 'score response')
        raise ProtocolError, "score output exceeds #{max_output_bytes} bytes" if bytes.bytesize > max_output_bytes

        ScoreProviders.response(raw)
      end

      def generate(value, name)
        JSON.generate(value)
      rescue JSON::GeneratorError, EncodingError => e
        raise ProtocolError, "#{name} is not valid JSON: #{e.message}"
      end

      def positive_integer(value, name)
        number = Integer(value)
        raise ArgumentError, "#{name} must be positive" unless number.positive?

        number
      rescue ArgumentError, TypeError
        raise ArgumentError, "#{name} must be a positive integer"
      end
    end

    # One JSON request on stdin and one JSON response on stdout.
    class Command < Transport
      class OutputLimit < StandardError; end

      READ_CHUNK = 16 * 1024
      TERMINATION_GRACE = 0.1

      attr_reader :command, :timeout, :environment, :inherit_environment

      def initialize(command:, timeout: DEFAULT_TIMEOUT, environment: {},
                     inherit_environment: false, **options)
        super(**options)
        @command = Array(command).map(&:to_s).freeze
        @timeout = positive_timeout(timeout)
        @environment = environment.to_h { |name, value| [name.to_s, value.to_s] }.freeze
        @inherit_environment = !!inherit_environment # rubocop:disable Style/DoubleNegation
        raise ArgumentError, 'command is required' if @command.empty? || @command.any?(&:empty?)
      end

      def score(text, side:, **context)
        _payload, input = request_payload(text, side, context)
        output, status = execute(input)
        raise ProtocolError, exit_reason(status) unless status.success?

        response_payload(parse(output))
      end

      private

      def execute(input)
        Open3.popen3(environment, *command, unsetenv_others: !inherit_environment) do |stdin, stdout, stderr, wait|
          run_process(input, stdin, stdout, stderr, wait)
        end
      rescue Errno::ENOENT
        raise ProtocolError, "score command executable not found: #{command.first}"
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
        raise ProtocolError, "score command timed out after #{timeout} seconds"
      rescue OutputLimit
        terminate(wait)
        raise ProtocolError, "score output exceeds #{max_output_bytes} bytes"
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

      def parse(output)
        JSON.parse(output)
      rescue JSON::ParserError => e
        raise ProtocolError, "score command returned invalid JSON: #{e.message}"
      end

      def exit_reason(status)
        value = status.exitstatus || "signal #{status.termsig}"
        "score command exited with status #{value}"
      end

      def positive_timeout(value)
        number = Float(value)
        raise ArgumentError unless number.positive? && number.finite?

        number
      rescue ArgumentError, TypeError
        raise ArgumentError, 'timeout must be a positive finite number'
      end
    end

    # JSON endpoint transport using a caller-configured stdlib HTTP client.
    class Endpoint < Transport
      attr_reader :http, :path

      def initialize(http:, path: '/score', **options)
        super(**options)
        raise ArgumentError, 'http must respond to post_json' unless http.respond_to?(:post_json)

        @http = http
        @path = path.to_s.freeze
        raise ArgumentError, 'path is required' if @path.empty?
      end

      def score(text, side:, **context)
        payload, = request_payload(text, side, context)
        response_payload(http.post_json(path, payload))
      end
    end
  end
end
