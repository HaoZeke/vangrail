# frozen_string_literal: true

require_relative 'helper'

# The shared chat client, driven against a recorded HTTP double.
class TestChat < Minitest::Test
  PATH = '/chat/completions'

  def test_a_chat_needs_an_endpoint
    assert_raises(ArgumentError) { Vangrail::Chat.new(model: 'm') }
  end

  def test_a_null_content_falls_back_to_the_reasoning_field
    body = chat_body(nil)
    body['choices'][0]['message']['reasoning'] = "safe\n"
    http = StubHTTP.new(responses: { PATH => body })
    chat = Vangrail::Chat.new(model: 'm', http: http)
    rail = Vangrail::Rails::GuardModel.new(model: 'm', preset: :llama_guard, chat: chat)

    assert_predicate rail.call('x', side: :input), :certain?
  end
end
