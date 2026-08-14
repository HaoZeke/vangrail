# frozen_string_literal: true

require_relative 'client/completion'
require_relative 'errors'
require_relative 'http'
require_relative 'result'

module Vangrail
  # Interop with a NeMo Guardrails server that already exists.
  #
  # Nothing in this gem needs one. It is here for the case where a team already
  # runs the Python service, wants its configs to stay the source of truth, and
  # wants Ruby to call rather than reimplement. Reach for Config#engine first:
  # it runs the same folder in this process with nothing to deploy.
  #
  # `/v1/checks` is the endpoint that matches what a rail actually wants, and it
  # answers in the same three states this gem models: passed, modified, blocked.
  # Older servers do not have it, so `check` falls back to a chat completion with
  # generation switched off and reads the rail-tracking variables out of that.
  class Client
    CONFIGS_PATH = '/v1/rails/configs'
    CHECKS_PATH = '/v1/checks'
    COMPLETIONS_PATH = '/v1/chat/completions'
    PROTOCOLS = %i[auto nested flat].freeze

    RAIL_VARS = [Completion::INPUT_RAIL_VAR, Completion::OUTPUT_RAIL_VAR].freeze

    attr_reader :config_id, :model, :protocol, :http

    # True once /v1/checks has answered, false once it has 404ed, nil until one
    # of those happens, so a caller can report "not yet known" honestly.
    attr_reader :checks_supported

    def initialize(base_url:, config_id: nil, model: nil, api_key: nil, protocol: :auto,
                   open_timeout: HTTP::DEFAULT_OPEN_TIMEOUT, read_timeout: HTTP::DEFAULT_READ_TIMEOUT,
                   http: nil)
      raise ArgumentError, "protocol must be one of #{PROTOCOLS.join(', ')}" unless PROTOCOLS.include?(protocol)

      @config_id = config_id
      @model = model
      @protocol = protocol
      @checks_supported = nil
      @http = http || HTTP.new(
        base_url: base_url, api_key: api_key,
        open_timeout: open_timeout, read_timeout: read_timeout
      )
    end

    def base_url
      http.base_url
    end

    def configs
      body = http.get_json(CONFIGS_PATH)
      list = body.is_a?(Array) ? body : Array(body['configs'])
      list.filter_map { |entry| entry.is_a?(Hash) ? entry['id'] : entry.to_s }
    end

    def available?
      http.reachable?(CONFIGS_PATH)
    end

    def check_input(text, config_id: nil)
      check([{ 'role' => 'user', 'content' => text.to_s }], rail: :input, config_id: config_id)
    end

    def check_output(text, user_input: nil, config_id: nil)
      messages = []
      messages << { 'role' => 'user', 'content' => user_input.to_s } unless user_input.to_s.strip.empty?
      messages << { 'role' => 'assistant', 'content' => text.to_s }
      check(messages, rail: :output, config_id: config_id)
    end

    # Runs rails without generation and returns a Result.
    def check(messages, rail:, config_id: nil)
      chosen = config_id || @config_id
      if @checks_supported != false
        begin
          return from_checks(http.post_json(CHECKS_PATH, checks_payload(messages, rail, chosen)), rail)
        rescue HTTPError => e
          raise unless e.status == 404

          @checks_supported = false
        end
      end
      from_completion(chat(messages: messages, config_id: chosen, options: check_options(rail)), rail)
    end

    # A full guardrailed completion, for the case where the server generates the
    # answer as well as checking it.
    def chat(messages:, config_id: nil, config_ids: nil, options: nil, context: nil,
             thread_id: nil, model: nil, **extra)
      opts = merge_options(options)
      body = extra.merge(messages: normalize(messages))
      chosen = { config_id: config_id || @config_id, config_ids: config_ids }
      Completion.new(send_payload(body, chosen, opts, context, thread_id, model))
    end

    private

    def checks_payload(messages, rail, config_id)
      payload = { 'messages' => normalize(messages), 'rail_types' => [rail.to_s] }
      payload['config_id'] = config_id if config_id
      payload
    end

    # {"status": "passed"|"modified"|"blocked", "content": "...", "rail": "..."}
    def from_checks(body, rail)
      @checks_supported = true
      status = body['status'].to_s
      unless Result::STATUSES.map(&:to_s).include?(status)
        raise ProtocolError, "/v1/checks answered status #{status.inspect}"
      end

      Result.new(status: status.to_sym, rail: body['rail'] || rail.to_s,
                 content: body['content'], raw: body)
    end

    def from_completion(completion, rail)
      return Result.passed(rail: rail.to_s, raw: completion.raw) if completion.allowed?

      reason = completion.triggered_rail || completion.stopped_rails.first&.dig('name')
      Result.blocked(rail: reason || rail.to_s, content: completion.content, reason: reason,
                     raw: completion.raw)
    end

    def check_options(rail)
      { 'rails' => { 'input' => rail == :input, 'output' => rail == :output, 'dialog' => false } }
    end

    def merge_options(options)
      base = { 'output_vars' => RAIL_VARS.dup, 'log' => { 'activated_rails' => true } }
      return base unless options.is_a?(Hash)

      stringified = deep_stringify(options)
      merged = base.merge(stringified)
      merged['output_vars'] = (RAIL_VARS + Array(stringified['output_vars'])).uniq
      merged['log'] = base['log'].merge(stringified['log']) if stringified['log'].is_a?(Hash)
      merged
    end

    def send_payload(body, chosen, opts, context, thread_id, model)
      case protocol
      when :flat
        http.post_json(COMPLETIONS_PATH, flat_payload(body, chosen, opts, context, thread_id, model))
      when :nested
        http.post_json(COMPLETIONS_PATH, nested_payload(body, chosen, opts, context, thread_id, model))
      else
        try_nested_then_flat(body, chosen, opts, context, thread_id, model)
      end
    end

    def try_nested_then_flat(body, chosen, opts, context, thread_id, model)
      answer = http.post_json(COMPLETIONS_PATH, nested_payload(body, chosen, opts, context, thread_id, model))
      @protocol = :nested
      answer
    rescue HTTPError => e
      raise unless schema_rejection?(e)

      answer = http.post_json(COMPLETIONS_PATH, flat_payload(body, chosen, opts, context, thread_id, model))
      @protocol = :flat
      answer
    end

    # A 400/422 naming a field is the server saying it speaks the other shape.
    # Any other status is a real failure and stays raised.
    def schema_rejection?(error)
      return false unless [400, 422].include?(error.status)

      error.body.match?(/extra fields not permitted|unexpected keyword|field required|guardrails|config_id/i)
    end

    def nested_payload(body, chosen, opts, context, thread_id, model)
      guardrails = {}
      guardrails['config_id'] = chosen[:config_id] if chosen[:config_id]
      guardrails['config_ids'] = Array(chosen[:config_ids]) if chosen[:config_ids]
      guardrails['options'] = opts if opts
      guardrails['context'] = deep_stringify(context) if context
      guardrails['thread_id'] = thread_id if thread_id

      payload = body.transform_keys(&:to_s)
      payload['model'] = model || @model if model || @model
      payload['guardrails'] = guardrails unless guardrails.empty?
      payload
    end

    def flat_payload(body, chosen, opts, context, thread_id, model)
      payload = body.transform_keys(&:to_s)
      payload['config_id'] = chosen[:config_id] if chosen[:config_id]
      payload['config_ids'] = Array(chosen[:config_ids]) if chosen[:config_ids]
      payload['options'] = opts if opts
      payload['context'] = deep_stringify(context) if context
      payload['thread_id'] = thread_id if thread_id
      payload['model'] = model || @model if model || @model
      payload
    end

    def normalize(messages)
      Array(messages).map do |m|
        if m.is_a?(Hash)
          { 'role' => (m['role'] || m[:role]).to_s, 'content' => (m['content'] || m[:content]).to_s }
        else
          { 'role' => 'user', 'content' => m.to_s }
        end
      end
    end

    def deep_stringify(value)
      case value
      when Hash then value.to_h { |k, v| [k.to_s, deep_stringify(v)] }
      when Array then value.map { |v| deep_stringify(v) }
      else value
      end
    end
  end
end
