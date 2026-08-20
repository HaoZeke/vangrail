# frozen_string_literal: true

require 'digest'
require 'json'
require 'time'

module Vangrail
  # Immutable structured event emitted by enforcement operations.
  class AuditEvent
    attr_reader :id, :type, :at, :data

    def initialize(id:, type:, timestamp:, data:)
      @id = id.to_s.freeze
      @type = type.to_sym
      @at = timestamp.to_s.freeze
      @data = data.freeze
      freeze
    end

    def to_h
      { 'id' => id, 'type' => type.to_s, 'at' => at, 'data' => data }
    end
  end

  # In-memory audit stream that hashes labelled values before serialization.
  class AuditLog
    def initialize(clock: -> { Time.now.utc })
      @clock = clock
      @events = []
      @mutex = Mutex.new
    end

    def record(type, **data)
      @mutex.synchronize do
        event = AuditEvent.new(
          id: format('event-%06d', @events.length + 1),
          type: type,
          timestamp: timestamp,
          data: sanitize(data),
        )
        @events << event
        event
      end
    end

    def events
      @mutex.synchronize { @events.dup.freeze }
    end

    def record_call_attempt(call)
      record(
        :call_attempt,
        call_id: call.id,
        tool: call.tool,
        conversation_id: call.conversation_id,
        request: call.request,
        arguments: call.fields,
        sink: call.sink,
        confirmed: call.confirmed?,
        transaction: call.transaction?,
      )
    end

    def record_authorization(call:, allowed:, grant: nil, reason_code: nil, reason: nil)
      record(
        :authorization,
        call_id: call.id,
        grant_id: grant&.id,
        allowed: allowed,
        reason_code: reason_code,
        reason: reason,
      )
    end

    def to_h
      { 'events' => events.map(&:to_h) }
    end

    def to_json(*options)
      JSON.generate(to_h, *options)
    end

    private

    def timestamp
      value = @clock.call
      value.respond_to?(:iso8601) ? value.iso8601(6) : value.to_s
    end

    def sanitize(value)
      case value
      when Cell then sanitize_cell(value)
      when Call then sanitize_call(value)
      when Grant then sanitize_grant(value)
      when Hash
        value.each_with_object({}) do |(key, nested), clean|
          clean[key.to_s.freeze] = sanitize(nested)
        end.freeze
      when Array then value.map { |nested| sanitize(nested) }.freeze
      when Symbol then value.to_s.freeze
      when String then value.dup.freeze
      when Numeric, true, false, nil then value
      else value.class.name.to_s.freeze
      end
    end

    def sanitize_cell(cell)
      {
        'label' => sanitize(cell.label.to_h),
        'sha256' => Digest::SHA256.hexdigest(canonical(cell.raw)).freeze,
      }.freeze
    end

    def sanitize_call(call)
      {
        'id' => call.id,
        'tool' => call.tool.to_s,
        'conversation_id' => call.conversation_id,
        'request' => sanitize_cell(call.request),
        'arguments' => sanitize(call.fields),
        'sink' => call.sink&.to_s,
        'confirmed' => call.confirmed?,
        'transaction' => call.transaction?,
        'idempotency_key_sha256' => digest_optional(call.idempotency_key),
      }.compact.freeze
    end

    def sanitize_grant(grant)
      {
        'id' => grant.id,
        'tool' => grant.tool.to_s,
        'effect' => grant.effect.to_s,
        'arguments' => sanitize(grant.arguments),
        'sinks' => sanitize(grant.sinks),
        'uses' => grant.uses,
        'after' => sanitize(grant.after),
        'integrity' => sanitize(grant.integrity),
        'confirm' => grant.confirmation_required?,
        'transaction' => grant.transaction_required?,
        'conversation_id' => grant.conversation_id,
      }.compact.freeze
    end

    def digest_optional(value)
      Digest::SHA256.hexdigest(value).freeze unless value.to_s.empty?
    end

    def canonical(value)
      JSON.generate(canonical_value(value))
    rescue JSON::GeneratorError
      value.to_s
    end

    def canonical_value(value)
      case value
      when Hash
        value.keys.sort_by(&:to_s).to_h { |key| [key.to_s, canonical_value(value[key])] }
      when Array then value.map { |nested| canonical_value(nested) }
      when Symbol then value.to_s
      when String, Numeric, true, false, nil then value
      else value.to_s
      end
    end
  end
end
