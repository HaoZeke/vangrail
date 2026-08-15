# frozen_string_literal: true

require_relative '../lib/vangrail'

# Stands in for Vangrail::HTTP. Records every call and replays scripted
# answers, so the whole suite runs with no network and no server.
class StubHTTP
  attr_reader :calls, :base_url

  def initialize(base_url: 'http://stub.invalid/v1', responses: {}, raises: {})
    @base_url = base_url
    @responses = responses
    @raises = raises
    @calls = []
  end

  def get_json(path)
    record(:get, path, nil)
  end

  def post_json(path, payload)
    record(:post, path, payload)
  end

  def reachable?(path)
    get_json(path)
    true
  rescue Vangrail::HTTPError
    true
  rescue Vangrail::Error
    false
  end

  def last_payload
    @calls.reverse.detect { |c| c[:method] == :post }&.fetch(:payload)
  end

  private

  def record(method, path, payload)
    @calls << { method: method, path: path, payload: payload }
    key = path.to_s
    raise @raises[key] if @raises.key?(key)

    answer = @responses[key]
    answer = answer.call(payload, @calls.count { |c| c[:path] == key }) if answer.respond_to?(:call)
    raise answer if answer.is_a?(StandardError)

    answer || {}
  end
end

# Builds a chat-completion body around one assistant message.
def chat_body(content, extra = {})
  {
    'id' => 'chatcmpl-test',
    'object' => 'chat.completion',
    'model' => 'test-model',
    'choices' => [
      { 'index' => 0, 'message' => { 'role' => 'assistant', 'content' => content },
        'finish_reason' => 'stop' },
    ],
  }.merge(extra)
end
