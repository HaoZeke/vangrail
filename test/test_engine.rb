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

    assert_predicate result, :passed?
    refute_predicate result, :certain?
    assert_includes result.reason, 'no input rails'
  end

  def test_a_clean_pass_is_certain
    engine = Vangrail::Engine.new(input: [scripted(R.passed(rail: 'a'))])
    result = engine.check_input('hello')

    assert_predicate result, :passed?
    assert_predicate result, :certain?
  end

  def test_the_first_block_ends_the_pass
    second = scripted(R.passed(rail: 'second'), name: 'second')
    engine = Vangrail::Engine.new(input: [scripted(R.blocked(rail: 'first'), name: 'first'), second])
    result = engine.check_input('hello')

    assert_predicate result, :blocked?
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

    assert_predicate result, :modified?
    assert_equal 'key [redacted]', result.content
    assert_equal 'key [redacted]', downstream.seen.first[:text]
  end

  def test_a_later_block_beats_an_earlier_rewrite
    engine = Vangrail::Engine.new(
      output: [scripted(R.modified(rail: 'r', content: 'edited'), name: 'r'),
               scripted(R.blocked(rail: 'b', reason: 'policy'), name: 'b')],
    )
    result = engine.check_output('text')

    assert_predicate result, :blocked?
    assert_equal 'b', result.rail
    assert_equal 'edited', result.content
    assert_equal 'edited', result.content_or('text')
  end

  def test_a_block_after_an_uncertain_rail_is_not_a_certain_block
    engine = Vangrail::Engine.new(
      output: [scripted(R.unchecked(rail: 'missing', reason: 'no judge'), name: 'missing'),
               scripted(R.blocked(rail: 'b', reason: 'policy'), name: 'b')],
    )
    result = engine.check_output('text')

    assert_predicate result, :blocked?
    refute_predicate result, :certain?
  end

  def test_output_is_judged_as_usable_utf8
    secrets = Vangrail::Rails::Secrets.new
    raw = "Set api_key=sk-abcdefghij\xFFklmnopqrstuvwx1234 in the file.".dup
                                                                       .force_encoding(Encoding::ASCII_8BIT)
    result = Vangrail::Engine.new(output: [secrets]).check_output(raw)

    assert_predicate result, :modified?
    refute_includes result.content, 'sk-live-9c2f1'
    assert result.content.valid_encoding?
  end

  def test_rails_that_do_not_apply_to_the_side_are_skipped
    input_only = scripted(R.blocked(rail: 'input_only'), name: 'input_only', sides: [:input])
    engine = Vangrail::Engine.new(output: [input_only])
    result = engine.check_output('text')

    assert_predicate result, :passed?
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

    assert_predicate result, :passed?
    refute_predicate result, :certain?
    assert_includes result.reason, 'boom failed'
    assert_includes result.reason, 'TransportError'
  end

  def test_on_error_block_stops_the_turn
    engine = Vangrail::Engine.new(input: [ExplodingRail.new(name: 'boom')], on_error: :block)
    result = engine.check_input('hello')

    assert_predicate result, :blocked?
    refute_predicate result, :certain?
  end

  def test_a_failure_does_not_stop_the_rails_after_it
    later = scripted(R.blocked(rail: 'later', reason: 'caught it'), name: 'later')
    engine = Vangrail::Engine.new(input: [ExplodingRail.new(name: 'boom'), later])
    result = engine.check_input('hello')

    assert_predicate result, :blocked?
    assert_equal 'later', result.rail
  end

  # A pass where one rail failed is not the same as a clean pass, even when a
  # later rail cleared the text.
  def test_a_pass_after_a_failure_stays_uncertain
    engine = Vangrail::Engine.new(
      input: [ExplodingRail.new(name: 'boom'), scripted(R.passed(rail: 'ok'), name: 'ok')],
    )
    result = engine.check_input('hello')

    assert_predicate result, :passed?
    refute_predicate result, :certain?
  end

  def test_a_rail_returning_the_wrong_type_is_a_protocol_error_not_a_pass
    engine = Vangrail::Engine.new(input: [scripted(:yes_fine, name: 'sloppy')])
    result = engine.check_input('hello')

    refute_predicate result, :certain?
    assert_includes result.reason, 'ProtocolError'
  end

  def test_rejects_an_unknown_on_error
    assert_raises(ArgumentError) { Vangrail::Engine.new(on_error: :shrug) }
  end

  def test_rejects_an_unknown_side
    engine = Vangrail::Engine.new(input: [scripted(R.passed(rail: 'a'))])

    error = assert_raises(ArgumentError) { engine.rails(:sideways) }
    assert_includes error.message, 'unknown side'
  end

  # --- reporting ---

  def test_offline_is_true_only_when_every_rail_is_offline
    offline = Vangrail::Engine.new(input: [scripted(R.passed(rail: 'a'), offline: true)])

    assert_predicate offline, :offline?
    mixed = Vangrail::Engine.new(
      input: [scripted(R.passed(rail: 'a'), offline: true),
              scripted(R.passed(rail: 'b'), name: 'b', offline: false)],
    )

    refute_predicate mixed, :offline?
  end

  def test_an_empty_engine_is_not_offline
    refute_predicate Vangrail::Engine.new, :offline?
    assert_empty Vangrail::Engine.new
  end

  def test_describe_names_the_rails_per_side
    engine = Vangrail::Engine.new(
      input: [scripted(R.passed(rail: 'a'), name: 'patterns')],
      output: [scripted(R.passed(rail: 'b'), name: 'secrets', sides: [:output])],
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

  # Two rails cannot decide: one was never built, one tried and had its
  # connection refused. The second is the one worth telling the caller about.
  def test_a_rail_that_ran_reports_over_a_rail_that_was_never_built
    unbuilt = Vangrail::Rails::Missing.new(reason: 'no endpoint resolved', name: 'trajectory',
                                           sides: [:input])
    tried = Class.new(Vangrail::Rail) do
      def decide(_text, _context) = unchecked('policy_input failed: connection refused')
    end.new(name: 'policy_input', sides: [:input])

    result = Vangrail::Engine.new(input: [unbuilt, tried]).check_input('a question')

    assert_predicate result, :passed?
    refute_predicate result, :certain?
    assert_includes result.reason, 'connection refused'
    assert_equal 'policy_input', result.rail
  end

  # And when nothing ran at all, the placeholder is still what there is to say.
  def test_a_placeholder_reports_when_it_is_the_only_thing_uncertain
    unbuilt = Vangrail::Rails::Missing.new(reason: 'no endpoint resolved', name: 'trajectory',
                                           sides: [:input])
    result = Vangrail::Engine.new(input: [unbuilt]).check_input('a question')

    refute_predicate result, :certain?
    assert_includes result.reason, 'no endpoint resolved'
  end

  # A pass where two rails rewrote the text reported only the last of them, with
  # no categories at all, so a redaction followed by a disclosure mark looked
  # exactly like a mark on its own. The record whose purpose is to explain what
  # the desk did had stopped saying a credential was taken out.
  def test_every_rail_that_rewrote_the_text_is_named
    engine = Vangrail::Engine.new(
      output: [Vangrail::Rails::Secrets.new,
               Vangrail::Rails::Watermark.new(key: 'k', issuer: 'issuer')],
      cache: false
    )
    result = engine.check_output('Set api_key=sk-live-abcdefghijklmnop in the config.')

    assert_predicate result, :modified?
    assert_equal %w[secrets watermark], result.rewritten_by
    assert_equal 'watermark', result.rail, 'the reported rail is no longer the last rewriter'
    # Against the rail's own table rather than a literal, so the assertion
    # follows a renamed category and names no provider here.
    redaction = Vangrail::Rails::Secrets::DEFAULT_PATTERNS.keys
    assert_operator (result.categories & redaction).length, :>=, 1,
                    'the redacting rail contributed no category to the merged result'
    assert_includes result.categories, 'watermark'
    assert_equal %w[secrets watermark], result.to_h['rewritten_by']
  end

  def test_a_pass_with_one_rewrite_names_one
    engine = Vangrail::Engine.new(output: [Vangrail::Rails::Secrets.new], cache: false)
    result = engine.check_output('Set api_key=sk-live-abcdefghijklmnop in the config.')

    assert_equal ['secrets'], result.rewritten_by
  end

  def test_a_clean_pass_names_none
    engine = Vangrail::Engine.new(output: [Vangrail::Rails::Secrets.new], cache: false)
    result = engine.check_output('Nothing sensitive here.')

    assert_empty result.rewritten_by
    refute result.to_h.key?('rewritten_by')
  end

  # A block after a rewrite is still a pass in which text was changed, and both
  # facts belong in the report.
  def test_a_block_after_a_rewrite_keeps_the_rewrite_in_the_report
    engine = Vangrail::Engine.new(
      output: [Vangrail::Rails::Secrets.new,
               Vangrail::Rails::Pattern.new(patterns: { 'refuse' => /config/ }, name: 'refuser',
                                            sides: [:output])],
      cache: false
    )
    result = engine.check_output('Set api_key=sk-live-abcdefghijklmnop in the config.')

    assert_predicate result, :blocked?
    assert_equal 'refuser', result.rail
    assert_equal ['secrets'], result.rewritten_by
  end
end
