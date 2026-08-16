# frozen_string_literal: true

require 'json'
require_relative 'errors'
require_relative 'result'

module Vangrail
  # One JSON envelope for check, screen, and assess, used by the CLI and the
  # HTTP front. Foreign callers speak this, not MRI objects.
  class Front
    COMMANDS = %w[check_input check_output check_context screen assess].freeze

    attr_reader :engine

    def initialize(engine:)
      @engine = engine
    end

    def dispatch(command, payload = {})
      name = command.to_s.tr('-', '_')
      raise ArgumentError, "unknown command #{command}" unless COMMANDS.include?(name)

      send(name, stringify(payload))
    end

    def check_input(payload)
      result_payload(engine.check_input(required(payload, 'text'), context_of(payload)))
    end

    def check_output(payload)
      result_payload(engine.check_output(
                       required(payload, 'text'),
                       user_input: payload['user_input'],
                       passages: payload['passages'],
                       **context_of(payload)
                     ))
    end

    def check_context(payload)
      result_payload(engine.check_context(required(payload, 'text'), **context_of(payload)))
    end

    def screen(payload)
      documents = payload['documents']
      raise ArgumentError, 'documents is required' unless documents.is_a?(Array)

      screening = engine.screen(documents, **context_of(payload))
      {
        'kept' => screening.kept,
        'rejected' => screening.rejected.map do |entry|
          { 'document' => entry[:document], 'result' => result_payload(entry[:result]) }
        end,
        'certain' => screening.certain?,
        'reason' => screening.reason,
      }.compact
    end

    def assess(payload)
      prior = payload['prior']
      raise ArgumentError, 'prior is required' if prior.nil?

      side = (payload['side'] || 'input').to_sym
      engine.assess(required(payload, 'text'), side: side, prior: prior.to_f,
                    **context_of(payload)).to_h
    end

    def self.result_payload(result)
      body = result.to_h
      body['content'] = result.content unless result.content.nil?
      body
    end

    private

    def result_payload(result) = self.class.result_payload(result)

    def required(payload, key)
      value = payload[key]
      raise ArgumentError, "#{key} is required" if value.nil?

      value
    end

    def context_of(payload)
      extra = payload['context']
      extra.is_a?(Hash) ? symbolize(extra) : {}
    end

    def stringify(payload)
      payload.to_h.transform_keys(&:to_s)
    end

    def symbolize(hash)
      hash.to_h.transform_keys { |key| key.to_s.to_sym }
    end
  end
end
