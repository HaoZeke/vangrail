# frozen_string_literal: true

require_relative 'errors'
require_relative 'http'
require_relative 'result'
require_relative 'verdict'

module NemoGuardrails
  # Client for a running NeMo Guardrails server (`nemoguardrails server`).
  #
  # Two request shapes exist. The OpenAI-compatible one nests guardrails fields
  # under a `guardrails` object; the older one puts `config_id` and `options` at
  # the top level. `protocol: :auto` sends the nested shape, and on a 422 that
  # names an unknown or missing field it retries flat and remembers the answer,
  # so a mixed fleet needs no per-host configuration.
  class Server
    CONFIGS_PATH = '/v1/rails/configs'
    COMPLETIONS_PATH = '/v1/chat/completions'
    PROTOCOLS = %i[auto nested flat].freeze

    # Variables that carry which rail stopped a turn. Requested by default:
    # without them a caller cannot tell a rail block from a model refusal.
    RAIL_VARS = [Result::INPUT_RAIL_VAR, Result::OUTPUT_RAIL_VAR].freeze

    attr_reader :config_id, :model, :protocol, :http

    def initialize(base_url:, config_id: nil, model: nil, api_key: nil, protocol: :auto,
                   open_timeout: HTTP::DEFAULT_OPEN_TIMEOUT, read_timeout: HTTP::DEFAULT_READ_TIMEOUT,
                   http: nil)
      raise ArgumentError, "protocol must be one of #{PROTOCOLS.join(', ')}" unless PROTOCOLS.include?(protocol)

      @config_id = config_id
      @model = model
      @protocol = protocol
      @http = http || HTTP.new(
        base_url: base_url, api_key: api_key,
        open_timeout: open_timeout, read_timeout: read_timeout
      )
    end

    def base_url
      http.base_url
    end

    # Configuration ids the server has loaded.
    def configs
      body = http.get_json(CONFIGS_PATH)
      list = body.is_a?(Array) ? body : Array(body['configs'])
      list.filter_map do |entry|
        entry.is_a?(Hash) ? entry['id'] : entry.to_s
      end
    end

    def available?
      http.reachable?(CONFIGS_PATH)
    end

    # A guardrailed completion. Returns a Result; raises on transport or HTTP
    # failure so the caller decides whether an absent rail means allow or block.
    def chat(messages:, config_id: nil, config_ids: nil, options: nil, context: nil,
             thread_id: nil, model: nil, **extra)
      opts = merge_options(options)
      payload_extra = extra.merge(messages: normalize_messages(messages))
      chosen = { config_id: config_id || @config_id, config_ids: config_ids }
      Result.new(send_payload(payload_extra, chosen, opts, context, thread_id, model))
    end

    # Input rails only, on the user turn. Skips dialog and generation, so the
    # cost is the guard model and nothing else.
    def check_input(text, config_id: nil, context: nil)
      result = chat(
        messages: [{ role: 'user', content: text.to_s }],
        config_id: config_id,
        context: context,
        options: { rails: { input: true, output: false, dialog: false } }
      )
      verdict_for(result, :input)
    end

    # Output rails on an answer this application already produced. `user_input`
    # gives rails that compare answer to question something to compare against.
    def check_output(text, user_input: nil, config_id: nil, context: nil)
      messages = []
      messages << { role: 'user', content: user_input.to_s } if user_input.to_s.strip != ''
      messages << { role: 'assistant', content: text.to_s }
      result = chat(
        messages: messages,
        config_id: config_id,
        context: context,
        options: { rails: { input: false, output: true, dialog: false } }
      )
      verdict_for(result, :output)
    end

    private

    # The rail name comes from the triggered-rail variable when the server sent
    # it, and from the activated-rails log when it did not.
    def verdict_for(result, rail)
      return Verdict.allow(rail: rail, raw: result.raw, model: result.model) if result.allowed?

      reason = result.triggered_rail || result.stopped_rails.first&.dig('name')
      Verdict.block(rail: rail, reason: reason, raw: result.raw)
    end

    def merge_options(options)
      base = {
        'output_vars' => RAIL_VARS.dup,
        'log' => { 'activated_rails' => true }
      }
      return base unless options.is_a?(Hash)

      stringified = deep_stringify(options)
      merged = base.merge(stringified)
      merged['output_vars'] = (RAIL_VARS + Array(stringified['output_vars'])).uniq
      merged['log'] = base['log'].merge(stringified['log']) if stringified['log'].is_a?(Hash)
      merged
    end

    def send_payload(payload_extra, chosen, opts, context, thread_id, model)
      case protocol
      when :flat
        http.post_json(COMPLETIONS_PATH, flat_payload(payload_extra, chosen, opts, context, thread_id, model))
      when :nested
        http.post_json(COMPLETIONS_PATH, nested_payload(payload_extra, chosen, opts, context, thread_id, model))
      else
        try_nested_then_flat(payload_extra, chosen, opts, context, thread_id, model)
      end
    end

    def try_nested_then_flat(payload_extra, chosen, opts, context, thread_id, model)
      body = http.post_json(COMPLETIONS_PATH, nested_payload(payload_extra, chosen, opts, context, thread_id, model))
      @protocol = :nested
      body
    rescue HTTPError => e
      raise unless schema_rejection?(e)

      body = http.post_json(COMPLETIONS_PATH, flat_payload(payload_extra, chosen, opts, context, thread_id, model))
      @protocol = :flat
      body
    end

    # A 400/422 that names a field is the server telling us it speaks the other
    # shape. Any other status is a real failure and stays raised.
    def schema_rejection?(error)
      return false unless [400, 422].include?(error.status)

      error.body.match?(/extra fields not permitted|unexpected keyword|field required|guardrails|config_id/i)
    end

    def nested_payload(payload_extra, chosen, opts, context, thread_id, model)
      guardrails = {}
      guardrails['config_id'] = chosen[:config_id] if chosen[:config_id]
      guardrails['config_ids'] = Array(chosen[:config_ids]) if chosen[:config_ids]
      guardrails['options'] = opts if opts
      guardrails['context'] = deep_stringify(context) if context
      guardrails['thread_id'] = thread_id if thread_id

      body = payload_extra.transform_keys(&:to_s)
      body['model'] = model || @model if model || @model
      body['guardrails'] = guardrails unless guardrails.empty?
      body
    end

    def flat_payload(payload_extra, chosen, opts, context, thread_id, model)
      body = payload_extra.transform_keys(&:to_s)
      body['config_id'] = chosen[:config_id] if chosen[:config_id]
      body['config_ids'] = Array(chosen[:config_ids]) if chosen[:config_ids]
      body['options'] = opts if opts
      body['context'] = deep_stringify(context) if context
      body['thread_id'] = thread_id if thread_id
      body['model'] = model || @model if model || @model
      body
    end

    def normalize_messages(messages)
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
