# frozen_string_literal: true

module Vangrail
  # Opaque confirmation and transaction capabilities owned by a monitor.
  module ReferenceMonitorAuthority
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

    private

    def valid_confirmation?(call)
      token = @confirmations[call.id]
      token.equal?(call.confirmation) && token.fingerprint == call.fingerprint
    end

    def valid_transaction?(call)
      prepared = @transactions[call.id]
      prepared&.prepared? && prepared.fingerprint == call.fingerprint
    end
  end
end
