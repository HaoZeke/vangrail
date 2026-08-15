# frozen_string_literal: true

require_relative 'helper'

# The model-backed half of the multi-turn problem.
#
# What is tested here is the contract, not the model's judgement: when it asks,
# what it sends, and which kind of pass it reports when it does not ask. The
# verdict itself belongs to whatever model an application points it at.
class TestTrajectory < Minitest::Test
  include GuardrailsTest

  def http(verdict = '{"violation": 0}')
    StubHTTP.new(responses: { '/chat/completions' => chat_body(verdict) })
  end

  def rail(stub, **kwargs)
    Vangrail::Rails::Trajectory.new(chat: Vangrail::Chat.new(model: 'm', http: stub),
                                    model: 'm', **kwargs)
  end

  def turns(count)
    Array.new(count) do |i|
      { role: i.even? ? :user : :assistant, text: "message #{i}", blocked: false }
    end
  end

  # A two-message conversation has no trajectory, and the single-turn rails
  # have already read both messages. That is a judgement, so the pass is
  # certain.
  def test_a_short_conversation_is_a_certain_pass_and_costs_nothing
    stub = http
    result = rail(stub).call('the newest question', side: :input, history: turns(2))

    assert_predicate result, :passed?
    assert_predicate result, :certain?
    assert_empty stub.calls
  end

  def test_a_long_enough_conversation_is_judged
    stub = http
    result = rail(stub).call('the newest question', side: :input, history: turns(4))

    assert_predicate result, :passed?
    assert_equal 1, stub.calls.size
  end

  def test_a_verdict_against_the_sequence_blocks
    stub = http('{"violation": 1, "rule_ids": ["T1"], "rationale": "staged escalation"}')
    result = rail(stub).call('and now the last step', side: :input, history: turns(6))

    assert_predicate result, :blocked?
    assert_includes result.categories, 'T1'
  end

  # The transcript is the object being judged, so it has to arrive intact.
  def test_the_whole_transcript_is_sent_with_the_newest_message_last
    stub = http
    rail(stub).call('the newest question', side: :input, history: turns(4))
    sent = stub.calls.first[:payload]['messages'].last['content']

    assert_includes sent, 'message 0'
    assert_includes sent, 'message 3'
    assert_includes sent, 'the newest question'
    assert_operator sent.index('message 0'), :<, sent.index('the newest question')
  end

  def test_roles_are_labelled_in_the_transcript
    stub = http
    rail(stub).call('q', side: :input, history: turns(4))
    sent = stub.calls.first[:payload]['messages'].last['content']

    assert_includes sent, 'user: message 0'
    assert_includes sent, 'assistant: message 1'
  end

  # A round trip per turn is the cost, so skipping turns has to be possible.
  # A staged escalation takes several turns by construction and cannot finish
  # inside the gap.
  def test_it_can_judge_one_turn_in_two
    stub = http
    r = rail(stub, every: 2)

    skipped = r.call('q', side: :input, history: turns(5))

    refute_predicate skipped, :certain?, 'a skipped turn must not look like a clean check'
    assert_empty stub.calls

    judged = r.call('q', side: :input, history: turns(6))

    assert_predicate judged, :certain?
    assert_equal 1, stub.calls.size
  end

  def test_the_window_bounds_what_is_sent
    stub = http
    rail(stub, window: 4).call('q', side: :input, history: turns(20))
    sent = stub.calls.first[:payload]['messages'].last['content']

    refute_includes sent, 'message 0'
    assert_includes sent, 'message 19'
  end

  # An unparsed judge answer is not a clean pass, the same as everywhere else.
  def test_an_unreadable_verdict_is_an_uncertain_pass
    result = rail(http('I am not sure what to say about this')).call(
      'q', side: :input, history: turns(4)
    )

    assert_predicate result, :passed?
    refute_predicate result, :certain?
    assert_includes result.reason, 'unparsed'
  end

  def test_it_is_not_offline_and_not_memoizable
    r = rail(http)

    refute_predicate r, :offline?
    assert_nil r.cache_key('text', side: :input)
    assert r.applies_to?(:input)
    refute r.applies_to?(:output)
  end

  def test_it_needs_somewhere_to_call
    assert_raises(ArgumentError) { Vangrail::Rails::Trajectory.new }
  end
end
