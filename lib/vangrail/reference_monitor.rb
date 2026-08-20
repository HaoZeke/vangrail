# frozen_string_literal: true

require 'securerandom'
require_relative 'origin'
require_relative 'plan'

module Vangrail
  # Immutable attempt to exercise one tool grant.
  class Call
    attr_reader :id, :tool, :request, :arguments, :conversation_id, :sink,
                :idempotency_key

    def initialize(tool:, request:, arguments:, conversation_id:, sink: nil,
                   confirmed: false, transaction: false, idempotency_key: nil,
                   id: nil)
      raise ArgumentError, 'request must be a Cell' unless request.is_a?(Cell)

      @id = (id || SecureRandom.uuid).to_s.freeze
      @tool = tool.to_sym
      @request = request
      @arguments = arguments.is_a?(Cell) ? arguments : Cell.data(arguments)
      @conversation_id = conversation_id.to_s.freeze
      @sink = sink&.to_sym
      @confirmed = confirmed.equal?(true)
      @transaction = transaction.equal?(true)
      @idempotency_key = idempotency_key&.to_s&.freeze
      freeze
    end

    def confirmed?
      @confirmed
    end

    def transaction?
      @transaction
    end

    def fields
      return { value: arguments }.freeze unless arguments.value.is_a?(Hash)

      arguments.value.transform_keys(&:to_sym).freeze
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
    CONSTRAINT_KEYS = %i[type origins equals in pattern].freeze
    TYPES = {
      string: String,
      integer: Integer,
      number: Numeric,
      array: Array,
      hash: Hash,
    }.freeze

    attr_reader :plan

    def initialize(plan)
      raise ArgumentError, 'plan must be a Plan' unless plan.is_a?(Plan)

      @plan = plan.lock!
      @usage = Hash.new(0)
      @authorized = {}
      @finished = {}
      @completed = []
      @mutex = Mutex.new
    end

    def authorize(call)
      raise ArgumentError, 'call must be a Call' unless call.is_a?(Call)

      @mutex.synchronize do
        preliminary = preliminary_denial(call)
        return preliminary if preliminary

        denials = plan.grants_for(call.tool).map do |grant|
          denial = grant_denial(call, grant)
          next denial if denial

          @usage[grant.id] += 1
          authorization = Authorization.allow(call, grant)
          @authorized[call.id] = authorization
          return authorization
        end
        denials.compact.first || deny(call, :no_grant, "no grant for #{call.tool}")
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
        @finished[call.id]
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

    def grant_denial(call, grant)
      return deny(call, :argument_schema, 'argument names do not match the grant') unless schema_matches?(call, grant)

      call.fields.each do |name, cell|
        reason = constraint_denial(cell, grant.arguments.fetch(name))
        return deny(call, reason, "argument #{name} violates its grant") if reason
      end

      policy_denial(call, grant)
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
      return origin_denial(cell, constraint[:origins]) if constraint.key?(:origins) && origin_denial(cell, constraint[:origins])
      return :argument_literal if constraint.key?(:equals) && cell.raw != constraint[:equals]
      return :argument_value if constraint.key?(:in) && !Array(constraint[:in]).include?(cell.raw)
      return :argument_value if constraint.key?(:pattern) && !constraint[:pattern].match?(cell.raw.to_s)

      nil
    end

    def type_matches?(value, expected)
      return true if expected.nil?
      return value == true || value == false if expected == :boolean

      type = expected.is_a?(Class) ? expected : TYPES[expected.to_sym]
      type && value.is_a?(type)
    end

    def policy_denial(call, grant)
      return deny(call, :sink, 'call sink is outside the grant') unless sink_allowed?(call, grant)
      return deny(call, :integrity, 'request integrity is outside the grant') unless integrity_allowed?(call, grant)
      return deny(call, :confirmation, 'call requires confirmation') if grant.confirmation_required? && !call.confirmed?
      return deny(call, :transaction, 'call requires a transaction') if grant.transaction_required? && !call.transaction?
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

    def deny(call, code, reason)
      Authorization.deny(call, code, reason)
    end
  end
end
