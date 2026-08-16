# frozen_string_literal: true

require_relative 'helper'

# Grounding judge, driven against a recorded HTTP double.
class TestGrounding < Minitest::Test
  PATH = '/chat/completions'

  def chat_for(content)
    http = StubHTTP.new(responses: { PATH => chat_body(content) })
    [Vangrail::Chat.new(model: 'test/model', http: http), http]
  end

  def test_grounding_blocks_an_invented_identifier
    chat, http = chat_for('{"violation": 1, "policy_category": "G2", "rationale": "gpu_h200 appears in no passage"}')
    rail = Vangrail::Rails::Grounding.new(chat: chat, model: 'test/judge')
    result = rail.call('Use -p gpu_h200. [1]', side: :output,
                                               passages: [{ 'title' => 'GPU', 'text' => 'Use gpu_a100.' }])

    assert_predicate result, :blocked?
    assert_equal ['G2'], result.categories
    user = http.last_payload['messages'][1]['content']

    assert_includes user, '[1] GPU'
  end

  def test_grounding_without_passages_says_it_checked_nothing
    chat, = chat_for('{"violation": 0}')
    rail = Vangrail::Rails::Grounding.new(chat: chat, model: 'test/judge')
    result = rail.call('anything', side: :output, passages: [])

    assert_predicate result, :passed?
    refute_predicate result, :certain?
    assert_includes result.reason, 'no passages'
  end

  # Its verdict depends on the passages as well as the draft, so a changed
  # retrieval must be judged again.
  def test_grounding_is_never_memoized
    chat, = chat_for('{"violation": 0}')
    rail = Vangrail::Rails::Grounding.new(chat: chat, model: 'test/judge')

    assert_nil rail.cache_key('text', side: :output)
  end

  def test_grounding_runs_on_the_output_side_only
    chat, = chat_for('{"violation": 0}')
    rail = Vangrail::Rails::Grounding.new(chat: chat, model: 'test/judge')

    assert rail.applies_to?(:output)
    refute rail.applies_to?(:input)
  end
end
