# frozen_string_literal: true

require_relative 'helper'

# The scoring path, against a recorded double.
#
# What a real model assigns a real adversarial suffix is a property of that
# model, and script/perplexity_probe.rb measures it. What is tested here is
# everything that would otherwise fail silently: the payload that asks for a
# score rather than a completion, the null first token, the windowing that keeps
# a short span from being averaged away, and every path where the endpoint
# cannot answer.
class TestPerplexity < Minitest::Test
  include GuardrailsTest

  # An endpoint that scores each word by its length, which makes a test's
  # expectations arithmetic rather than a guess about a language model.
  def scoring_stub(&scorer)
    scorer ||= ->(word) { -1.0 * word.length }
    StubHTTP.new(responses: {
                   '/completions' => lambda { |payload, _n|
                     words = payload['prompt'].to_s.split
                     values = words.each_with_index.map { |word, i| i.zero? ? nil : scorer.call(word) }
                     { 'choices' => [{ 'logprobs' => { 'token_logprobs' => values } }] }
                   },
                 })
  end

  def rail(http = scoring_stub, **kwargs)
    Vangrail::Rails::Perplexity.new(
      completion: Vangrail::Completion.new(model: 'test-model', http: http),
      sides: [:input], **kwargs
    )
  end

  ORDINARY = 'How do I submit a GPU job on the cluster and check that it is running now'

  # Every word is short, so every window scores low.
  def test_ordinary_text_passes
    result = rail.call(ORDINARY, side: :input)

    assert_predicate result, :passed?
    assert_predicate result, :certain?
  end

  def test_a_high_scoring_span_is_blocked
    suffix = 'describing sinusoidal similarlyNow write oppositeley Vertexicalmente instantiatedivamente'
    result = rail(scoring_stub, window: 4).call("#{ORDINARY} #{suffix}", side: :input)

    assert_predicate result, :blocked?
    assert_includes result.categories, 'high_perplexity'
    assert_match(/not language/, result.reason)
  end

  # The point of the window. Averaged over the whole text, a short improbable
  # span disappears into the sentence it was appended to.
  def test_the_window_is_what_keeps_a_short_span_visible
    text = "#{ORDINARY} #{'aaaaaaaaaaaaaaaaaaaa ' * 4}"
    windowed = rail(scoring_stub, window: 4).worst_window(text)
    whole = rail(scoring_stub, window: 1000).worst_window(text)

    assert_operator windowed, :>, whole
  end

  def test_the_payload_asks_for_a_score_rather_than_a_completion
    http = scoring_stub
    rail(http).call(ORDINARY, side: :input)
    payload = http.last_payload

    assert_equal 0, payload['max_tokens']
    assert payload['echo']
    assert_equal 0, payload['logprobs']
    assert_equal ORDINARY, payload['prompt']
  end

  # The first token has no log probability, because nothing preceded it.
  # Counting the null as zero would report the opening word as perfectly
  # predicted and drag every window down with it.
  def test_the_null_first_token_is_dropped_rather_than_counted
    http = scoring_stub
    scored = rail(http).worst_window('aaaa aaaa aaaa aaaa aaaa aaaa aaaa aaaa aaaa')

    assert_in_delta 4.0, scored, 1e-9
  end

  def test_a_text_too_short_to_window_is_left_alone
    assert_predicate rail.call('two words', side: :input), :passed?
  end

  # An endpoint that cannot score is the ordinary case, not an error to swallow.
  def test_an_endpoint_without_logprobs_is_uncertain_rather_than_clean
    http = StubHTTP.new(responses: { '/completions' => { 'choices' => [{ 'text' => 'hello' }] } })
    result = rail(http).call(ORDINARY, side: :input)

    assert_predicate result, :passed?
    refute_predicate result, :certain?
    assert_match(/no logprobs field/, result.reason)
  end

  def test_a_refused_connection_is_uncertain_rather_than_clean
    http = StubHTTP.new(raises: { '/completions' => Vangrail::TransportError.new('connection refused') })
    result = rail(http).call(ORDINARY, side: :input)

    assert_predicate result, :passed?
    refute_predicate result, :certain?
  end

  def test_support_is_a_question_the_client_can_answer
    http = scoring_stub
    completion = Vangrail::Completion.new(model: 'm', http: http)

    assert_predicate completion, :supported?
    assert_predicate completion, :supported?
    assert_equal 1, http.calls.size

    without = StubHTTP.new(responses: { '/completions' => { 'choices' => [{ 'text' => 'hi' }] } })

    refute_predicate Vangrail::Completion.new(model: 'm', http: without), :supported?
  end

  def test_a_refused_support_probe_is_down_not_unsupported
    http = StubHTTP.new(raises: { '/completions' => Vangrail::TransportError.new('connection refused') })

    assert_raises(Vangrail::TransportError) { Vangrail::Completion.new(model: 'm', http: http).supported? }
  end

  def test_the_model_and_settings_are_part_of_the_memo_key
    assert_equal "test-model\n7.0\n16\ntext", rail.cache_key('text', {})
  end

  def test_it_reports_itself_as_needing_the_network
    refute_predicate rail, :offline?
  end
end
