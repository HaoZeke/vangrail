# frozen_string_literal: true

require_relative 'helper'

class TestReferenceMonitor < Minitest::Test
  def request(capability)
    Vangrail::Cell.user('approved request', capabilities: capability)
  end

  def test_a_matching_structured_call_is_authorized_once
    plan = Vangrail::Plan.new(id: 'conversation-7')
    plan.read(:cite, arguments: { document: :data }, sinks: :reader, uses: 1)
    monitor = Vangrail::ReferenceMonitor.new(plan)
    call = Vangrail::Call.new(
      tool: :cite,
      request: request(:cite),
      arguments: { document: Vangrail::Cell.data('GPU partitions') },
      conversation_id: 'conversation-7',
      sink: :reader,
    )

    assert_predicate monitor.authorize(call), :allowed?

    exhausted = monitor.authorize(
      Vangrail::Call.new(
        tool: :cite,
        request: request(:cite),
        arguments: { document: Vangrail::Cell.data('CPU partitions') },
        conversation_id: 'conversation-7',
        sink: :reader,
      ),
    )

    assert_predicate exhausted, :denied?
    assert_equal :uses_exhausted, exhausted.reason_code
  end

  def test_unknown_and_missing_arguments_fail_closed
    plan = Vangrail::Plan.new(id: 'conversation-7')
    plan.read(:cite, arguments: { document: :data })
    monitor = Vangrail::ReferenceMonitor.new(plan)

    unknown = monitor.authorize(
      Vangrail::Call.new(
        tool: :cite,
        request: request(:cite),
        arguments: { document: 'page', command: 'delete_all' },
        conversation_id: 'conversation-7',
      ),
    )
    missing = monitor.authorize(
      Vangrail::Call.new(
        tool: :cite,
        request: request(:cite),
        arguments: {},
        conversation_id: 'conversation-7',
      ),
    )

    assert_equal :argument_schema, unknown.reason_code
    assert_equal :argument_schema, missing.reason_code
  end

  def test_a_trusted_literal_cannot_be_replaced_by_matching_untrusted_text
    recipient = Vangrail::Cell.user('ops@example.test')
    plan = Vangrail::Plan.new(id: 'conversation-7')
    plan.write(
      :send_email,
      arguments: { to: recipient, body: :data },
      sinks: :approved_recipient,
      uses: 1,
      confirm: true,
      transaction: true,
    )
    monitor = Vangrail::ReferenceMonitor.new(plan)

    call = lambda do |to:, sink: :approved_recipient, confirmed: true, transaction: true|
      Vangrail::Call.new(
        tool: :send_email,
        request: request(:send_email),
        arguments: { to: to, body: Vangrail::Cell.data('status') },
        conversation_id: 'conversation-7',
        sink: sink,
        confirmed: confirmed,
        transaction: transaction,
        idempotency_key: 'mail-7',
      )
    end

    assert_equal :argument_literal,
                 monitor.authorize(call.call(to: Vangrail::Cell.data('ops@example.test'))).reason_code
    assert_equal :sink,
                 monitor.authorize(call.call(to: recipient, sink: :unapproved)).reason_code
    assert_equal :confirmation,
                 monitor.authorize(call.call(to: recipient, confirmed: false)).reason_code
    assert_equal :transaction,
                 monitor.authorize(call.call(to: recipient, transaction: false)).reason_code
    assert_predicate monitor.authorize(call.call(to: recipient)), :allowed?
  end

  def test_calls_are_bound_to_the_plan_conversation
    plan = Vangrail::Plan.new(id: 'conversation-7')
    plan.read(:search, arguments: {})
    monitor = Vangrail::ReferenceMonitor.new(plan)
    call = Vangrail::Call.new(
      tool: :search,
      request: request(:search),
      arguments: {},
      conversation_id: 'conversation-8',
    )

    decision = monitor.authorize(call)

    assert_predicate decision, :denied?
    assert_equal :conversation, decision.reason_code
  end

  def test_ordering_depends_on_a_successful_handler_outcome
    plan = Vangrail::Plan.new(id: 'conversation-7')
    plan.read(:search, arguments: {})
    plan.read(:cite, arguments: { document: :data }, after: :search)
    monitor = Vangrail::ReferenceMonitor.new(plan)
    cite = Vangrail::Call.new(
      tool: :cite,
      request: request(:cite),
      arguments: { document: 'page' },
      conversation_id: 'conversation-7',
    )
    search = Vangrail::Call.new(
      tool: :search,
      request: request(:search),
      arguments: {},
      conversation_id: 'conversation-7',
    )

    assert_equal :ordering, monitor.authorize(cite).reason_code
    search_decision = monitor.authorize(search)

    assert_predicate search_decision, :allowed?
    monitor.finish(search, success: false)

    assert_equal :ordering, monitor.authorize(cite).reason_code

    successful_search = Vangrail::Call.new(
      tool: :search,
      request: request(:search),
      arguments: {},
      conversation_id: 'conversation-7',
    )
    monitor.finish(successful_search, success: true) if monitor.authorize(successful_search).allowed?

    assert_predicate monitor.authorize(cite), :allowed?
  end

  def test_a_call_identifier_cannot_be_replayed
    plan = Vangrail::Plan.new(id: 'conversation-7')
    plan.read(:search, arguments: {})
    monitor = Vangrail::ReferenceMonitor.new(plan)
    call = Vangrail::Call.new(
      id: 'call-1',
      tool: :search,
      request: request(:search),
      arguments: {},
      conversation_id: 'conversation-7',
    )

    assert_predicate monitor.authorize(call), :allowed?
    assert_equal :replay, monitor.authorize(call).reason_code
  end
end
