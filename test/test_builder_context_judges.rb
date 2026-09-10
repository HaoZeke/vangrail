# frozen_string_literal: true

require_relative 'helper'

# Whether the two model-backed context rails can be switched on at all.
#
# In their own file rather than beside the other builder tests, which is a
# smaller reason than it looks: the commit hook on this machine reads the whole
# staged file, and appending to that one restages a line it objects to.
class TestBuilderContextJudges < Minitest::Test
  # A rail nobody can switch on is a rail that does not exist. These two were
  # written, tested and measured before they were reachable from
  # GUARDRAILS_RAILS, which is how a gem ships a feature nobody can use.
  def test_the_context_judges_are_reachable_by_name
    engine = Vangrail::Builder.new({ 'GUARDRAILS_RAILS' => 'context,task_relation,task_drift' }).engine
    names = engine.context_rails.map(&:name)

    assert_includes names, 'task_relation'
    assert_includes names, 'task_drift'
  end

  # And off unless asked for, because each is a call per screened document.
  def test_they_are_off_by_default
    names = Vangrail::Builder.new({ 'GUARDRAILS_RAILS' => 'context' }).engine.context_rails.map(&:name)

    refute_includes names, 'task_relation'
    refute_includes names, 'task_drift'
  end

  # With no endpoint they are placeholders that report an unchecked pass, not
  # rails that quietly approve every document.
  def test_without_an_endpoint_they_say_so
    engine = Vangrail::Builder.new({ 'GUARDRAILS_RAILS' => 'context,task_relation' }).engine
    rail = engine.context_rails.detect { |r| r.name == 'task_relation' }

    assert_predicate rail, :placeholder?
    result = rail.call('a page', side: :context, user_input: 'a question')
    refute_predicate result, :certain?
    refute_predicate result, :blocked?
  end

  def test_the_uncertainty_policy_comes_from_the_environment
    assert_equal :allow, Vangrail::Builder.new({}).engine.on_uncertain
    assert_equal :block, Vangrail::Builder.new({ 'GUARDRAILS_ON_UNCERTAIN' => 'block' }).engine.on_uncertain
    assert_equal :block, Vangrail::Builder.new({ 'GUARDRAILS_ON_UNCERTAIN' => 'BLOCK' }).engine.on_uncertain
  end
end
