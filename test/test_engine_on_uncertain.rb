# frozen_string_literal: true

require_relative 'helper'

# Which way to fail when a rail ran and could not decide is a real choice, and
# the published systems disagree: Meta's LlamaFirewall answers "treating as
# potentially compromised for safety" when its alignment scanner errors. The
# default here is the other way and this is the switch.
class TestEngineOnUncertain < Minitest::Test
  class Undecided < Vangrail::Rail
    def decide(_text, _context) = unchecked('endpoint refused')
  end

  def test_an_undecided_rail_passes_uncertain_by_default
    engine = Vangrail::Engine.new(input: [Undecided.new(name: 'quiet', sides: [:input])])
    result = engine.check_input('a question')

    assert_predicate result, :passed?
    refute_predicate result, :certain?
    assert_equal 'endpoint refused', result.reason
  end

  def test_on_uncertain_block_refuses_instead
    engine = Vangrail::Engine.new(input: [Undecided.new(name: 'quiet', sides: [:input])],
                                  on_uncertain: :block)
    result = engine.check_input('a question')

    assert_predicate result, :blocked?
    refute_predicate result, :certain?
    assert_equal 'endpoint refused', result.reason
    assert_equal ['unchecked'], result.categories
  end

  # Named for the rail that could not check, so a refusal can be traced to it.
  def test_blocking_on_uncertainty_names_the_rail_that_could_not_decide
    engine = Vangrail::Engine.new(input: [Undecided.new(name: 'the_judge', sides: [:input])],
                                  on_uncertain: :block)

    assert_equal 'the_judge', engine.check_input('a question').rail
  end

  # A rail that decided cleanly is not affected by the policy.
  def test_a_decided_pass_is_untouched_by_the_policy
    engine = Vangrail::Engine.new(input: [Vangrail::Rails::Pattern.new(patterns: /\Anever matches\z/)],
                                  on_uncertain: :block)
    result = engine.check_input('an ordinary question')

    assert_predicate result, :passed?
    assert_predicate result, :certain?
  end

  def test_an_unreadable_policy_is_refused_at_construction
    assert_raises(ArgumentError) { Vangrail::Engine.new(input: [], on_uncertain: :maybe) }
  end
end
