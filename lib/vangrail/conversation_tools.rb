# frozen_string_literal: true

module Vangrail
  # Planning and monitored tool execution for a Conversation.
  module ConversationTools
    # Names the tools this question is allowed to use before retrieved data is
    # visible. Selecting a name never creates a Grant.
    def intend(*names)
      raise Error, 'ask before intending a tool' unless last_user_turn
      raise PrivilegeError, 'the plan is locked: data has already been seen' if locked?

      names.each do |name|
        name = name.to_sym
        raise ArgumentError, "unknown tool #{name}" unless tools.key?(name)
        raise PrivilegeError, "capability #{name} is denied by profile" if profile.denied?(name)

        @intended << name unless @intended.include?(name)
      end
      intended
    end

    def intended
      @intended.dup.freeze
    end

    def locked?
      @locked
    end

    # Compatibility query for the coarse Admission API. Actual execution also
    # requires a matching structured Grant from the ReferenceMonitor.
    def admit?(capability, arguments: nil)
      turn = last_user_turn
      return false unless turn
      return false if profile.denied?(capability)

      args = case arguments
             when nil then nil
             when Cell then arguments
             else Cell.data(arguments)
             end
      admission.permit?(capability, request: Cell.user(turn.text, capabilities: capabilities),
                                    arguments: args)
    end

    # Runs a handler only after profile, plan, hook, and reference-monitor
    # authorization agree. Every refusal is recorded without calling the
    # handler.
    def invoke(target, arguments: nil, sink: nil, confirmed: false, transaction: false,
               idempotency_key: nil)
      call = target if target.is_a?(Call)
      name = call ? call.tool : target.to_sym
      raise ArgumentError, "unknown tool #{name}" unless tools.key?(name)

      handler_arguments = call ? call.arguments.raw : arguments
      refusal = preauthorization_refusal(name, handler_arguments, call)
      return refusal if refusal

      call ||= build_call(name, arguments, sink: sink, confirmed: confirmed,
                                           transaction: transaction,
                                           idempotency_key: idempotency_key)
      authorization = monitor.authorize(call)
      return authorization_refusal(name, handler_arguments, call, authorization) if authorization.denied?

      execute_authorized(name, handler_arguments, call, authorization)
    end

    def invoked?(name)
      invocations.any? { |row| row[:name] == name.to_sym && row[:result].allowed? }
    end

    def child_env(source = ENV)
      profile.strip_secrets? ? Profile.strip_secrets(source) : source.to_h
    end

    private

    def preauthorization_refusal(name, arguments, call)
      if profile.denied?(name)
        return refuse(name, arguments, 'deny', "capability #{name} is denied by profile", call: call)
      end
      if profile.readonly? && !tools.readonly?(name)
        return refuse(name, arguments, 'profile', "profile #{profile.name} is read-only", call: call)
      end

      hook = run_pre_invoke(name, arguments, call)
      return hook if hook
      return if @intended.include?(name)

      refuse(name, arguments, 'plan', "capability #{name} was not intended", call: call)
    end

    def authorization_refusal(name, arguments, call, authorization)
      reason = "#{authorization.reason_code}: #{authorization.reason}"
      refuse(name, arguments, 'reference_monitor', reason, call: call,
                                                           authorization: authorization)
    end

    def execute_authorized(name, arguments, call, authorization)
      value = tools.fire(name, arguments, self)
      monitor.finish(call, success: true)
      cell = value.is_a?(Cell) ? value : Cell.tool(value)
      result = Result.passed(rail: name.to_s)
      record_invocation(name, arguments, result, cell, call: call, authorization: authorization)
      result
    rescue StandardError => e
      monitor.finish(call, success: false)
      refuse(name, arguments, 'handler', "#{e.class}: #{e.message}", call: call,
                                                                     authorization: authorization)
    end

    def run_pre_invoke(name, arguments, call)
      hook = @hooks[:pre_invoke]
      return nil unless hook

      verdict = hook.call(name, arguments, self)
      if verdict.is_a?(Result)
        record_invocation(name, arguments, verdict, nil, call: call)
        return verdict
      end
      return nil if verdict

      refuse(name, arguments, 'hook', "pre_invoke refused #{name}", call: call)
    end

    def refuse(name, arguments, rail, reason, call: nil, authorization: nil)
      Result.blocked(rail: rail, reason: reason).tap do |result|
        record_invocation(name, arguments, result, nil, call: call, authorization: authorization)
      end
    end

    def record_invocation(name, arguments, result, cell, call: nil, authorization: nil)
      @invocations << {
        name: name,
        arguments: arguments,
        result: result,
        cell: cell,
        call: call,
        authorization: authorization,
      }.compact
      turn = self.class::Turn.new(role: :tool, text: name.to_s, result: result, origin: Origin.tool)
      @turns << turn
      @session&.fold(result, origin: turn.origin, side: :output)
    end

    def build_call(name, arguments, sink:, confirmed:, transaction:, idempotency_key:)
      turn = last_user_turn
      raise Error, 'ask before invoking a tool' unless turn

      Call.new(
        tool: name,
        request: Cell.user(turn.text, capabilities: capabilities),
        arguments: arguments,
        conversation_id: plan.id,
        sink: sink,
        confirmed: confirmed,
        transaction: transaction,
        idempotency_key: idempotency_key,
      )
    end
  end
end
