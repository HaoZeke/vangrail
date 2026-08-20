# frozen_string_literal: true

require 'securerandom'
require 'digest'
require_relative 'audit'
require_relative 'origin'
require_relative 'plan'
require_relative 'result'

module Vangrail
  # Immutable attempt to exercise one tool grant.
  class Call
    attr_reader :id, :tool, :request, :arguments, :conversation_id, :sink,
                :idempotency_key, :confirmation

    def initialize(tool:, request:, arguments:, conversation_id:, sink: nil,
                   confirmation: nil, transaction: false, idempotency_key: nil,
                   id: nil)
      raise ArgumentError, 'request must be a Cell' unless request.is_a?(Cell)

      @id = (id || SecureRandom.uuid).to_s.freeze
      @tool = tool.to_sym
      @request = request
      payload = arguments.nil? ? {} : arguments
      @arguments = payload.is_a?(Cell) ? payload : Cell.data(payload)
      @conversation_id = conversation_id.to_s.freeze
      @sink = sink&.to_sym
      @confirmation = confirmation
      @transaction = transaction.equal?(true)
      @idempotency_key = idempotency_key&.to_s&.freeze
      freeze
    end

    def confirmed?
      !confirmation.nil?
    end

    def transaction?
      @transaction
    end

    def fields
      return { value: arguments }.freeze unless arguments.value.is_a?(Hash)

      arguments.value.transform_keys(&:to_sym).freeze
    end

    def with_confirmation(token)
      self.class.new(
        id: id,
        tool: tool,
        request: request,
        arguments: arguments,
        conversation_id: conversation_id,
        sink: sink,
        confirmation: token,
        transaction: transaction?,
        idempotency_key: idempotency_key,
      )
    end

    def fingerprint
      material = [
        tool,
        request.raw,
        request.label.to_h,
        fields.sort_by { |name, _| name.to_s }.map { |name, cell| [name, cell.raw, cell.label.to_h] },
        conversation_id,
        sink,
        transaction?,
        idempotency_key,
      ]
      Digest::SHA256.hexdigest(Marshal.dump(material))
    end

    def to_h
      {
        'id' => id,
        'tool' => tool.to_s,
        'conversation_id' => conversation_id,
        'arguments' => arguments.to_h,
        'sink' => sink&.to_s,
        'confirmed' => confirmed?,
        'transaction' => transaction?,
        'idempotency_key' => idempotency_key,
      }.compact
    end
  end

  # Opaque confirmation registered by a ReferenceMonitor for one exact Call.
  class Confirmation
    attr_reader :id, :call_id, :fingerprint, :actor

    def initialize(call, actor)
      @id = SecureRandom.uuid.freeze
      @call_id = call.id
      @fingerprint = call.fingerprint.freeze
      @actor = actor
      freeze
    end
  end

  # Authorization result with a stable machine-readable reason.
  class Authorization
    attr_reader :call, :grant, :reason_code, :reason

    def initialize(call:, allowed:, grant: nil, reason_code: nil, reason: nil)
      @call = call
      @allowed = allowed
      @grant = grant
      @reason_code = reason_code&.to_sym
      @reason = reason
      freeze
    end

    def self.allow(call, grant)
      new(call: call, allowed: true, grant: grant)
    end

    def self.deny(call, reason_code, reason)
      new(call: call, allowed: false, reason_code: reason_code, reason: reason)
    end

    def allowed?
      @allowed
    end

    def denied?
      !allowed?
    end

    def to_h
      {
        'allowed' => allowed?,
        'call_id' => call.id,
        'grant_id' => grant&.id,
        'reason_code' => reason_code&.to_s,
        'reason' => reason,
      }.compact
    end
  end

  # Complete authorization point for calls routed through the public adapter.
  class ReferenceMonitor
    CONSTRAINT_KEYS = %i[type origins integrity equals in pattern].freeze
    TYPES = {
      string: String,
      integer: Integer,
      number: Numeric,
      array: Array,
      hash: Hash,
    }.freeze

    attr_reader :plan, :audit

    def initialize(plan)
      raise ArgumentError, 'plan must be a Plan' unless plan.is_a?(Plan)

      @plan = plan.lock!
      @audit = @plan.audit
      @usage = Hash.new(0)
      @authorized = {}
      @claimed = {}
      @finished = {}
      @confirmations = {}
      @transactions = {}
      @completed = []
      @mutex = Mutex.new
    end

    def authorize(call, risk: nil)
      raise ArgumentError, 'call must be a Call' unless call.is_a?(Call)

      @mutex.synchronize do
        audit.record_call_attempt(call)
        preliminary = preliminary_denial(call)
        return audited(preliminary) if preliminary

        denials = plan.grants_for(call.tool).map do |grant|
          denial = grant_denial(call, grant, risk)
          next denial if denial

          @usage[grant.id] += 1
          authorization = Authorization.allow(call, grant)
          @authorized[call.id] = authorization
          return audited(authorization)
        end
        audited(denials.compact.first || deny(call, :no_grant, "no grant for #{call.tool}"))
      end
    end

    def finish(call, success:)
      raise ArgumentError, 'call must be a Call' unless call.is_a?(Call)

      @mutex.synchronize do
        authorization = @authorized[call.id]
        return false unless authorization&.allowed?
        return @finished[call.id] if @finished.key?(call.id)

        @finished[call.id] = success.equal?(true)
        @completed << call.tool if success
        audit.record(:handler_outcome, call_id: call.id, tool: call.tool,
                                       success: @finished[call.id])
        @finished[call.id]
      end
    end

    def claim(authorization)
      return false unless authorization.is_a?(Authorization)

      @mutex.synchronize do
        call_id = authorization.call.id
        return false unless @authorized[call_id].equal?(authorization)
        return false if @claimed[call_id] || @finished.key?(call_id)

        @claimed[call_id] = true
      end
    end

    def confirm(call, actor:)
      raise ArgumentError, 'call must be a Call' unless call.is_a?(Call)
      raise PrivilegeError, 'confirmation requires a privileged actor' unless actor.is_a?(Cell) && actor.privileged?

      @mutex.synchronize do
        raise PrivilegeError, 'call belongs to another conversation' if call.conversation_id != plan.id

        grants = plan.grants_for(call.tool)
        raise PrivilegeError, "call #{call.tool} has no confirmation grant" unless grants.any?(&:confirmation_required?)
        raise PrivilegeError, 'authorized calls cannot be reconfirmed' if @authorized.key?(call.id)

        Confirmation.new(call, actor).tap do |token|
          @confirmations[call.id] = token
          audit.record(:confirmation, call_id: call.id, confirmation_id: token.id, actor: actor)
        end
      end
    end

    def prepare_transaction(call, prepared)
      raise ArgumentError, 'call must be a Call' unless call.is_a?(Call)
      unless prepared.is_a?(PreparedTransaction) && prepared.tool == call.tool &&
             prepared.call_id == call.id && prepared.fingerprint == call.fingerprint
        raise PrivilegeError, 'transaction does not match the call'
      end

      @mutex.synchronize do
        raise PrivilegeError, 'call belongs to another conversation' if call.conversation_id != plan.id
        raise PrivilegeError, 'authorized calls cannot be prepared' if @authorized.key?(call.id)

        @transactions[call.id] = prepared
        audit.record(:transaction_prepared, call_id: call.id, transaction_id: prepared.id,
                                            tool: call.tool)
        prepared
      end
    end

    def finish_transaction(prepared, committed:)
      @mutex.synchronize do
        return false unless @transactions[prepared.call_id].equal?(prepared)

        type = committed ? :transaction_committed : :transaction_rolled_back
        audit.record(type, call_id: prepared.call_id, transaction_id: prepared.id,
                           tool: prepared.tool)
        true
      end
    end

    def usage(grant)
      grant_id = grant.respond_to?(:id) ? grant.id : grant.to_s
      @mutex.synchronize { @usage[grant_id] }
    end

    private

    def preliminary_denial(call)
      return deny(call, :conversation, 'call belongs to another conversation') if call.conversation_id != plan.id
      return deny(call, :replay, 'call identifier was already authorized') if @authorized.key?(call.id)
      return deny(call, :request_integrity, 'request lacks privileged integrity') unless call.request.privileged?

      capabilities = call.request.capabilities
      return if capabilities.nil? || capabilities.include?(call.tool)

      deny(call, :capability, "request lacks capability #{call.tool}")
    end

    def grant_denial(call, grant, risk)
      return deny(call, :argument_schema, 'argument names do not match the grant') unless schema_matches?(call, grant)

      call.fields.each do |name, cell|
        reason = constraint_denial(cell, grant.arguments.fetch(name))
        return deny(call, reason, "argument #{name} violates its grant") if reason
      end

      policy_denial(call, grant, risk)
    end

    def schema_matches?(call, grant)
      call.fields.keys.sort == grant.arguments.keys.sort
    end

    def constraint_denial(cell, constraint)
      case constraint
      when Cell then literal_denial(cell, constraint)
      when Symbol, Array then origin_denial(cell, constraint)
      when Class then cell.raw.is_a?(constraint) ? nil : :argument_type
      when Hash then hash_constraint_denial(cell, constraint)
      else cell.raw == constraint ? nil : :argument_literal
      end
    end

    def literal_denial(cell, literal)
      return :argument_literal unless literal.privileged? && cell.privileged?
      return :argument_literal unless cell.raw == literal.raw

      nil
    end

    def origin_denial(cell, allowed)
      origins = Array(allowed).map(&:to_sym)
      accepted = cell.origins.all? { |origin| origin.privileged? || origins.include?(origin.kind) }
      accepted ? nil : :argument_origin
    end

    def hash_constraint_denial(cell, constraint)
      return :argument_constraint unless (constraint.keys - CONSTRAINT_KEYS).empty?
      return :argument_type unless type_matches?(cell.raw, constraint[:type])

      if constraint.key?(:origins)
        origin_reason = origin_denial(cell, constraint[:origins])
        return origin_reason if origin_reason
      end
      if constraint.key?(:integrity)
        required = Array(constraint[:integrity]).map(&:to_sym)
        return :argument_integrity unless required.all? { |principal| cell.integrity.include?(principal) }
      end
      return :argument_literal if constraint.key?(:equals) && cell.raw != constraint[:equals]
      return :argument_value if constraint.key?(:in) && !Array(constraint[:in]).include?(cell.raw)
      return :argument_value if constraint.key?(:pattern) && !constraint[:pattern].match?(cell.raw.to_s)

      nil
    end

    def type_matches?(value, expected)
      return true if expected.nil?
      return [true, false].include?(value) if expected == :boolean

      type = expected.is_a?(Class) ? expected : TYPES[expected.to_sym]
      type && value.is_a?(type)
    end

    def policy_denial(call, grant, risk)
      return deny(call, :sink, 'call sink is outside the grant') unless sink_allowed?(call, grant)
      return deny(call, :integrity, 'request integrity is outside the grant') unless integrity_allowed?(call, grant)
      if grant.confirmation_required? && !valid_confirmation?(call)
        return deny(call, :confirmation, 'call requires a monitor-issued confirmation')
      end
      if grant.transaction_required? && !valid_transaction?(call)
        return deny(call, :transaction, 'call requires a prepared transaction')
      end

      risk_reason = risk_denial(call, risk)
      return risk_reason if risk_reason
      if grant.effect != :read && call.idempotency_key.to_s.empty?
        return deny(call, :idempotency, 'side-effecting call requires an idempotency key')
      end
      return deny(call, :ordering, 'grant dependencies have not completed') unless (grant.after - @completed).empty?
      return deny(call, :uses_exhausted, 'grant use count is exhausted') if grant.uses && @usage[grant.id] >= grant.uses

      nil
    end

    def sink_allowed?(call, grant)
      return false if grant.sinks && !grant.sinks.include?(call.sink)

      call.fields.values.all? do |cell|
        cell.confidentiality.nil? || cell.confidentiality.include?(call.sink)
      end
    end

    def integrity_allowed?(call, grant)
      return true if grant.integrity.nil?

      call.request.integrity.all? { |principal| grant.integrity.include?(principal) }
    end

    def valid_confirmation?(call)
      token = @confirmations[call.id]
      token.equal?(call.confirmation) && token.fingerprint == call.fingerprint
    end

    def valid_transaction?(call)
      prepared = @transactions[call.id]
      prepared&.prepared? && prepared.fingerprint == call.fingerprint
    end

    def risk_denial(call, risk)
      return nil if risk.nil?
      return deny(call, :risk_invalid, 'risk restriction has an invalid type') unless risk.is_a?(Result)
      return deny(call, :risk_blocked, 'risk policy blocked the call') if risk.blocked?
      return deny(call, :risk_uncertain, 'risk policy could not clear the call') unless risk.certain?

      nil
    end

    def deny(call, code, reason)
      Authorization.deny(call, code, reason)
    end

    def audited(authorization)
      audit.record_authorization(
        call: authorization.call,
        grant: authorization.grant,
        allowed: authorization.allowed?,
        reason_code: authorization.reason_code,
        reason: authorization.reason,
      )
      authorization
    end
  end
end
