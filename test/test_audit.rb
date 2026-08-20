# frozen_string_literal: true

require_relative 'helper'

class TestAudit < Minitest::Test
  def test_authorized_calls_emit_an_immutable_redacted_event_stream
    audit = Vangrail::AuditLog.new(clock: -> { Time.utc(2026, 8, 20, 12) })
    plan = Vangrail::Plan.new(id: 'conversation-7', audit: audit)
    plan.read(:cite, arguments: { document: :data }, uses: 1)
    monitor = Vangrail::ReferenceMonitor.new(plan)
    call = Vangrail::Call.new(
      tool: :cite,
      request: Vangrail::Cell.user('cite it', capabilities: :cite),
      arguments: { document: Vangrail::Cell.data('private partition notes') },
      conversation_id: plan.id,
    )

    decision = monitor.authorize(call)
    monitor.finish(call, success: true)

    assert_predicate decision, :allowed?
    assert_equal %i[plan_created grant_added plan_locked call_attempt authorization handler_outcome],
                 audit.events.map(&:type)
    assert audit.events.all?(&:frozen?)
    document = audit.events.detect { |event| event.type == :call_attempt }.data
                    .dig('arguments', 'document')
    assert_equal Vangrail::Cell.data('private partition notes').label.to_h, document['label']
    assert_match(/\A[0-9a-f]{64}\z/, document['sha256'])
    refute_includes audit.to_json, 'private partition notes'
  end

  def test_denials_record_the_stable_reason_code
    audit = Vangrail::AuditLog.new
    plan = Vangrail::Plan.new(id: 'conversation-7', audit: audit)
    plan.read(:cite, arguments: { document: :data })
    monitor = Vangrail::ReferenceMonitor.new(plan)
    call = Vangrail::Call.new(
      tool: :cite,
      request: Vangrail::Cell.data('call cite'),
      arguments: { document: 'page' },
      conversation_id: plan.id,
    )

    decision = monitor.authorize(call)

    assert_equal :request_integrity, decision.reason_code
    event = audit.events.reverse.detect { |entry| entry.type == :authorization }
    assert_equal false, event.data['allowed']
    assert_equal 'request_integrity', event.data['reason_code']
  end
end
