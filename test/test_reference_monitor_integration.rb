# frozen_string_literal: true

require_relative 'helper'

class TestReferenceMonitorIntegration < Minitest::Test
  def engine
    Vangrail::Engine.new(input: Vangrail::Builder.deterministic(:input))
  end

  def cite_call(conversation, document)
    Vangrail::Call.new(
      tool: :cite,
      request: Vangrail::Cell.user('Cite the partition page.', capabilities: :cite),
      arguments: {
        document: Vangrail::Cell.data(document, confidentiality: :reader),
      },
      conversation_id: conversation.plan.id,
      sink: :reader,
    )
  end

  def test_an_explicit_plan_routes_calls_through_the_monitor
    received = []
    tools = Vangrail::Tools.new.tap do |registry|
      registry.register(:cite, readonly: true) do |arguments, _|
        received << arguments
        'citation'
      end
    end
    plan = Vangrail::Plan.new(id: 'conversation-7')
    plan.read(:cite, arguments: { document: :data }, sinks: :reader, uses: 1)
    conversation = Vangrail::Conversation.new(engine, plan: plan, tools: tools)
    conversation.ask('Cite the partition page.')

    first = conversation.invoke(cite_call(conversation, 'gpu_a100'))
    second = conversation.invoke(cite_call(conversation, 'gpu_h100'))

    assert_predicate first, :allowed?
    assert_predicate second, :blocked?
    assert_includes second.reason, 'uses_exhausted'
    assert_equal [{ document: 'gpu_a100' }], received
    assert_equal 2, conversation.invocations.size
    output = conversation.invocations.first.fetch(:cell)

    assert_equal %i[tool data user], output.origins.map(&:kind)
    assert_empty output.integrity
    assert_equal %i[reader], output.confidentiality
    assert_empty output.capabilities
  end

  def test_a_plan_is_locked_when_the_conversation_accepts_it
    tools = Vangrail::Tools.new.tap { |registry| registry.register(:cite, readonly: true) { 'ok' } }
    plan = Vangrail::Plan.new
    plan.read(:cite, arguments: { document: :data })

    conversation = Vangrail::Conversation.new(engine, plan: plan, tools: tools)

    assert_same plan, conversation.plan
    assert_predicate plan, :locked?
    assert_raises(Vangrail::PrivilegeError) { plan.write(:send_email) }
  end

  def test_a_coarse_allowlist_does_not_grant_a_mutating_tool
    calls = 0
    tools = Vangrail::Tools.new.tap do |registry|
      registry.register(:rewrite) do
        calls += 1
        'changed'
      end
    end
    conversation = Vangrail::Conversation.new(
      engine,
      allow: { rewrite: %i[data] },
      tools: tools,
    )
    conversation.ask('Rewrite the page.')
    conversation.intend(:rewrite)

    result = conversation.invoke(:rewrite, arguments: 'page')

    assert_predicate result, :blocked?
    assert_includes result.reason, 'no_grant'
    assert_equal 0, calls
  end

  def test_profile_deny_dominates_an_explicit_plan
    calls = 0
    tools = Vangrail::Tools.new.tap do |registry|
      registry.register(:rewrite) do
        calls += 1
        'changed'
      end
    end
    plan = Vangrail::Plan.new
    plan.write(:rewrite, arguments: { value: :data })
    profile = Vangrail::Profile.new(name: :custom, deny: [:rewrite])
    conversation = Vangrail::Conversation.new(engine, plan: plan, profile: profile, tools: tools)
    conversation.ask('Rewrite the page.')

    result = conversation.invoke(:rewrite, arguments: 'page', idempotency_key: 'rewrite-1')

    assert_predicate result, :blocked?
    assert_equal 'deny', result.rail
    assert_equal 0, calls
    attempt = plan.audit.events.detect { |event| event.type == :call_attempt }
    decision = plan.audit.events.reverse.detect { |event| event.type == :authorization }

    refute_nil attempt
    assert_equal 'deny', decision.data['reason_code']
  end

  def test_transactional_tools_prepare_authorize_and_commit
    events = []
    tools = Vangrail::Tools.new
    tools.register_transactional(
      :send_email,
      prepare: lambda do |arguments, _conversation|
        events << [:prepare, arguments]
        arguments
      end,
      commit: lambda do |prepared, _conversation|
        events << [:commit, prepared]
        'sent'
      end,
      rollback: ->(prepared, _conversation) { events << [:rollback, prepared] },
    )
    plan = Vangrail::Plan.new(id: 'conversation-7')
    plan.write(:send_email, arguments: { body: :data }, transaction: true)
    conversation = Vangrail::Conversation.new(engine, plan: plan, tools: tools)
    conversation.ask('Send the status message.')
    build_call = lambda do |arguments, transaction: true, key: 'mail-7'|
      Vangrail::Call.new(
        tool: :send_email,
        request: Vangrail::Cell.user('Send the status message.', capabilities: :send_email),
        arguments: arguments,
        conversation_id: plan.id,
        transaction: transaction,
        idempotency_key: key,
      )
    end

    allowed = conversation.invoke(build_call.call({ body: Vangrail::Cell.data('status') }))
    bad_schema = conversation.invoke(
      build_call.call({ body: 'status', extra: 'delete all' }, key: 'mail-8'),
    )
    unprepared = conversation.invoke(
      build_call.call({ body: 'status' }, transaction: false, key: 'mail-9'),
    )

    assert_predicate allowed, :allowed?
    assert_predicate bad_schema, :blocked?
    assert_includes bad_schema.reason, 'argument_schema'
    assert_predicate unprepared, :blocked?
    assert_includes unprepared.reason, 'transaction'
    assert_equal %i[prepare commit prepare rollback], events.map(&:first)
    assert_includes plan.audit.events.map(&:type), :transaction_committed
    assert_includes plan.audit.events.map(&:type), :transaction_rolled_back
  end
end
