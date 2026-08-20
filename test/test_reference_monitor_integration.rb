# frozen_string_literal: true

require_relative 'helper'

class TestReferenceMonitorIntegration < Minitest::Test
  def engine
    Vangrail::Engine.new(input: Vangrail::Builder.deterministic(:input))
  end

  def test_an_explicit_plan_routes_calls_through_the_monitor
    received = []
    tools = Vangrail::Tools.new.tap do |registry|
      registry.register(:cite, readonly: true) { |arguments, _| received << arguments }
    end
    plan = Vangrail::Plan.new(id: 'conversation-7')
    plan.read(:cite, arguments: { document: :data }, uses: 1)
    conversation = Vangrail::Conversation.new(engine, plan: plan, tools: tools)
    conversation.ask('Cite the partition page.')

    first = conversation.invoke(
      Vangrail::Call.new(
        tool: :cite,
        request: Vangrail::Cell.user('Cite the partition page.', capabilities: :cite),
        arguments: { document: Vangrail::Cell.data('gpu_a100') },
        conversation_id: conversation.plan.id,
      ),
    )
    second = conversation.invoke(
      Vangrail::Call.new(
        tool: :cite,
        request: Vangrail::Cell.user('Cite the partition page.', capabilities: :cite),
        arguments: { document: Vangrail::Cell.data('gpu_h100') },
        conversation_id: conversation.plan.id,
      ),
    )

    assert_predicate first, :allowed?
    assert_predicate second, :blocked?
    assert_includes second.reason, 'uses_exhausted'
    assert_equal [{ document: 'gpu_a100' }], received
    assert_equal 2, conversation.invocations.size
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
  end
end
