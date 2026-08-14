# frozen_string_literal: true

require_relative 'helper'

# Ordering, short-circuiting, how a rewrite travels, and what happens when a
# rail raises.
class TestEngine < Minitest::Test
  include GuardrailsTest

  R = Vangrail::Result

  def scripted(result, **kwargs)
    ScriptedRail.new(result, **kwargs)
  end

  def test_no_rails_passes_but_says_it_checked_nothing
    result = Vangrail::Engine.new.check_input('anything')
    assert result.passed?
    refute result.certain?
    assert_includes result.reason, 'no input rails'
  end

  def test_a_clean_pass_is_certain
    engine = Vangrail::Engine.new(input: [scripted(R.passed(rail: 'a'))])
    result = engine.check_input('hello')
    assert result.passed?
    assert result.certain?
  end

  def test_the_first_block_ends_the_pass
    second = scripted(R.passed(rail: 'second'), name: 'second')
    engine = Vangrail::Engine.new(input: [scripted(R.blocked(rail: 'first'), name: 'first'), second])
    result = engine.check_input('hello')
    assert result.blocked?
    assert_equal 'first', result.rail
    assert_empty second.seen
  end

  # The rewrite has to reach the rails after it, or a redaction rail followed by
  # a policy rail judges text nobody will see.
  def test_a_rewrite_travels_to_later_rails
    downstream = scripted(R.passed(rail: 'downstream'), name: 'downstream')
    redactor = scripted(R.modified(rail: 'redactor', content: 'key [redacted]'), name: 'redactor')
    engine = Vangrail::Engine.new(output: [redactor, downstream])
    result = engine.check_output('key sk-abc')
    assert result.modified?
    assert_equal 'key [redacted]', result.content
    assert_equal 'key [redacted]', downstream.seen.first[:text]
  end

  def test_a_later_block_beats_an_earlier_rewrite
    engine = Vangrail::Engine.new(
      output: [scripted(R.modified(rail: 'r', content: 'edited'), name: 'r'),
               scripted(R.blocked(rail: 'b', reason: 'policy'), name: 'b')]
    )
    result = engine.check_output('text')
    assert result.blocked?
    assert_equal 'b', result.rail
  end

  def test_rails_that_do_not_apply_to_the_side_are_skipped
    input_only = scripted(R.blocked(rail: 'input_only'), name: 'input_only', sides: [:input])
    engine = Vangrail::Engine.new(output: [input_only])
    result = engine.check_output('text')
    assert result.passed?
    assert_empty input_only.seen
  end

  def test_context_carries_the_side_and_the_user_turn
    rail = scripted(R.passed(rail: 'a'))
    Vangrail::Engine.new(output: [rail]).check_output('answer', user_input: 'question',
                                                            passages: [{ 'text' => 'p' }])
    context = rail.seen.first[:context]
    assert_equal :output, context[:side]
    assert_equal 'question', context[:user_input]
    assert_equal 1, context[:passages].size
  end

  # --- failure ---

  def test_a_raising_rail_fails_open_and_marks_the_pass_uncertain
    engine = Vangrail::Engine.new(input: [ExplodingRail.new(name: 'boom')])
    result = engine.check_input('hello')
    assert result.passed?
    refute result.certain?
    assert_includes result.reason, 'boom failed'
    assert_includes result.reason, 'TransportError'
  end

  def test_on_error_block_stops_the_turn
    engine = Vangrail::Engine.new(input: [ExplodingRail.new(name: 'boom')], on_error: :block)
    result = engine.check_input('hello')
    assert result.blocked?
    refute result.certain?
  end

  def test_a_failure_does_not_stop_the_rails_after_it
    later = scripted(R.blocked(rail: 'later', reason: 'caught it'), name: 'later')
    engine = Vangrail::Engine.new(input: [ExplodingRail.new(name: 'boom'), later])
    result = engine.check_input('hello')
    assert result.blocked?
    assert_equal 'later', result.rail
  end

  # A pass where one rail failed is not the same as a clean pass, even when a
  # later rail cleared the text.
  def test_a_pass_after_a_failure_stays_uncertain
    engine = Vangrail::Engine.new(
      input: [ExplodingRail.new(name: 'boom'), scripted(R.passed(rail: 'ok'), name: 'ok')]
    )
    result = engine.check_input('hello')
    assert result.passed?
    refute result.certain?
  end

  def test_a_rail_returning_the_wrong_type_is_a_protocol_error_not_a_pass
    engine = Vangrail::Engine.new(input: [scripted(:yes_fine, name: 'sloppy')])
    result = engine.check_input('hello')
    refute result.certain?
    assert_includes result.reason, 'ProtocolError'
  end

  def test_rejects_an_unknown_on_error
    assert_raises(ArgumentError) { Vangrail::Engine.new(on_error: :shrug) }
  end

  # --- reporting ---

  def test_offline_is_true_only_when_every_rail_is_offline
    offline = Vangrail::Engine.new(input: [scripted(R.passed(rail: 'a'), offline: true)])
    assert offline.offline?
    mixed = Vangrail::Engine.new(
      input: [scripted(R.passed(rail: 'a'), offline: true),
              scripted(R.passed(rail: 'b'), name: 'b', offline: false)]
    )
    refute mixed.offline?
  end

  def test_an_empty_engine_is_not_offline
    refute Vangrail::Engine.new.offline?
    assert Vangrail::Engine.new.empty?
  end

  def test_describe_names_the_rails_per_side
    engine = Vangrail::Engine.new(
      input: [scripted(R.passed(rail: 'a'), name: 'patterns')],
      output: [scripted(R.passed(rail: 'b'), name: 'secrets', sides: [:output])]
    )
    assert_includes engine.describe, 'input=patterns'
    assert_includes engine.describe, 'output=secrets'
    assert_equal 'no rails', Vangrail::Engine.new.describe
  end

  def test_to_h_lists_rails_and_settings
    engine = Vangrail::Engine.new(input: [scripted(R.passed(rail: 'a'), name: 'patterns')])
    h = engine.to_h
    assert_equal ['patterns'], h['input']
    assert_equal 'allow', h['on_error']
    assert h.key?('cache')
  end
end
