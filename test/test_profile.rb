# frozen_string_literal: true

require_relative 'helper'

# Grok Build's session-pinned profile: deny wins, secrets do not
# inherit, a read-only posture cannot invoke a mutating tool.
class TestProfile < Minitest::Test
  include GuardrailsTest

  def engine
    Vangrail::Engine.new(input: Vangrail::Builder.deterministic(:input),
                         context: Vangrail::Builder.deterministic(:context))
  end

  def tools
    Vangrail::Tools.new.tap do |set|
      set.register(:cite, readonly: true) { |args, _| Vangrail::Cell.text_of(args) }
      set.register(:delete_all) { |_args, _| 'deleted' }
      set.register(:dump_secrets) { |_args, _| 'sk-live' }
      set.register(:rewrite) { |_args, _| 'rewritten' }
    end
  end

  def test_workspace_deny_wins_even_if_the_plan_named_the_tool
    convo = Vangrail::Conversation.new(engine, prior: 1e-3, profile: :workspace, tools: tools)
    convo.ask('Which GPU partitions exist?')
    convo.intend(:cite, :delete_all)
    convo.screen([{ 'text' => 'The GPU partitions are gpu_a100 and gpu_h100.' }])
    refused = convo.invoke(:delete_all, arguments: 'x')

    assert_predicate refused, :blocked?
    assert_equal 'deny', refused.rail
    refute convo.invoked?(:delete_all)
  end

  def test_strict_refuses_a_mutating_tool
    convo = Vangrail::Conversation.new(engine, prior: 1e-3, profile: :strict, tools: tools)
    convo.ask('Which GPU partitions exist?')
    convo.intend(:cite, :rewrite)
    convo.screen([{ 'text' => 'The GPU partitions are gpu_a100 and gpu_h100.' }])

    assert_predicate convo.invoke(:cite, arguments: 'gpu_a100'), :allowed?
    assert_equal 'profile', convo.invoke(:rewrite, arguments: 'x').rail
  end

  def test_child_env_drops_key_secret_and_token
    convo = Vangrail::Conversation.new(engine, prior: 1e-3, profile: :workspace, tools: tools)
    filtered = convo.child_env('PATH' => '/bin', 'SERVICE_API_KEY' => 'sk',
                               'HUB_TOKEN' => 't', 'HOME' => '/home/x')

    assert_equal '/bin', filtered['PATH']
    assert_equal '/home/x', filtered['HOME']
    refute filtered.key?('SERVICE_API_KEY')
    refute filtered.key?('HUB_TOKEN')
  end

  def test_a_pre_invoke_hook_can_still_block
    hook = ->(name, _args, _convo) { name != :cite }
    convo = Vangrail::Conversation.new(engine, prior: 1e-3, profile: :workspace, tools: tools,
                                     hooks: { pre_invoke: hook })
    convo.ask('Which GPU partitions exist?')
    convo.intend(:cite)
    convo.screen([{ 'text' => 'gpu_a100' }])
    refused = convo.invoke(:cite, arguments: 'gpu_a100')

    assert_predicate refused, :blocked?
    assert_equal 'hook', refused.rail
  end

  def test_deny_glob_matches_dump_secrets
    assert Vangrail::Profile.workspace.denied?(:dump_secrets)
    assert Vangrail::Profile.workspace.denied?(:delete_all)
    refute Vangrail::Profile.workspace.denied?(:cite)
  end

  def test_a_named_profile_refuses_extra_allow_or_deny
    assert_raises(ArgumentError) { Vangrail::Profile.resolve(:workspace, allow: { search: [] }) }
    assert_raises(ArgumentError) { Vangrail::Profile.resolve(:strict, deny: ['cite']) }
    assert_raises(ArgumentError) { Vangrail::Profile.resolve(:off, allow: { cite: %i[data] }) }
    assert_equal :workspace, Vangrail::Profile.resolve(:workspace).name
  end

  def test_hash_composition_is_deny_wins
    custom = Vangrail::Profile.resolve(nil, allow: { cite: %i[data], search: [] }, deny: ['cite'])

    assert custom.denied?(:cite)
    refute custom.allow.key?(:cite)
    assert_equal [], custom.allow[:search]
    assert_equal :custom, custom.name
  end

  def test_readonly_is_false_for_a_missing_tool
    set = tools

    assert_equal true, set.readonly?(:cite)
    assert_equal false, set.readonly?(:delete_all)
    assert_equal false, set.readonly?(:unknown)
  end

  def test_from_rails_predicates_are_booleans
    actions = Vangrail::Actions.from_rails

    assert_equal false, actions['self_check_input'].call({}, { text: 'x' })
    assert_equal false, actions['self_check_output'].call({}, { text: 'x' })
    assert_equal false, actions['self_check_facts'].call({}, { text: 'x' })
  end
end
