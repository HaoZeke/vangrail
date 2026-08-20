# frozen_string_literal: true

require_relative 'helper'

class TestPlan < Minitest::Test
  def test_a_plan_carries_immutable_structured_grants
    plan = Vangrail::Plan.new(id: 'conversation-7')
    grant = plan.read(
      :cite,
      arguments: { document: :data },
      sinks: :reader,
      uses: 2,
      after: :search,
    )

    assert_equal 'conversation-7', plan.id
    assert_equal :cite, grant.tool
    assert_equal :read, grant.effect
    assert_equal({ document: :data }, grant.arguments)
    assert_equal %i[reader], grant.sinks
    assert_equal 2, grant.uses
    assert_equal %i[search], grant.after
    assert_predicate grant, :frozen?
    assert_predicate grant.arguments, :frozen?
  end

  def test_locking_a_plan_prevents_authority_from_being_added
    plan = Vangrail::Plan.new
    grant = plan.read(:cite, arguments: { document: :data })

    plan.lock!

    assert_predicate plan, :locked?
    assert_same grant, plan.grant_for(:cite)
    assert_raises(Vangrail::PrivilegeError) { plan.write(:send_email) }
  end

  def test_compatibility_allowlists_compile_only_read_tools
    tools = Vangrail::Tools.new
    tools.register(:cite, readonly: true) { 'citation' }
    tools.register(:rewrite) { 'changed' }

    plan = Vangrail::Plan.from_allow(
      { cite: %i[data], rewrite: %i[data] },
      tools: tools,
    )

    assert_equal :read, plan.grant_for(:cite).effect
    assert_equal({ value: :data }, plan.grant_for(:cite).arguments)
    assert_nil plan.grant_for(:rewrite)
  end

  def test_write_grants_name_confirmation_and_transaction_requirements
    plan = Vangrail::Plan.new
    grant = plan.write(
      :send_email,
      arguments: { to: Vangrail::Cell.user('ops@example.test'), body: :data },
      sinks: :approved_recipient,
      uses: 1,
      confirm: true,
      transaction: true,
    )

    assert_equal :write, grant.effect
    assert_predicate grant, :confirmation_required?
    assert_predicate grant, :transaction_required?
    assert_equal 'ops@example.test', grant.arguments[:to].raw
  end
end
