# frozen_string_literal: true

require 'minitest/autorun'
require_relative 'stub_http'

# The memo and its refusals: what it stores, what it never stores, and what it
# treats as a different question.
class TestVerdictCache < Minitest::Test
  PATH = '/chat/completions'

  def allow_verdict
    NemoGuardrails::Verdict.allow(rail: :input)
  end

  def test_a_second_call_with_the_same_text_does_not_reach_the_block
    cache = NemoGuardrails::VerdictCache.new
    calls = 0
    2.times do
      cache.fetch(:input, 'm', 'same question') do
        calls += 1
        allow_verdict
      end
    end
    assert_equal 1, calls
    assert_equal 1, cache.hits
    assert_equal 1, cache.misses
  end

  def test_a_different_model_is_a_different_key
    cache = NemoGuardrails::VerdictCache.new
    cache.fetch(:input, 'model-a', 'q') { allow_verdict }
    cache.fetch(:input, 'model-b', 'q') { allow_verdict }
    assert_equal 2, cache.misses
  end

  def test_a_different_rail_is_a_different_key
    cache = NemoGuardrails::VerdictCache.new
    cache.fetch(:input, 'm', 'text') { allow_verdict }
    cache.fetch(:output, 'm', 'text') { allow_verdict }
    assert_equal 2, cache.misses
    assert_equal 2, cache.size
  end

  # An uncertain verdict records a rail that failed or did not run. Storing it
  # would turn one unlucky moment into a session-long hole.
  def test_an_uncertain_verdict_is_never_stored
    cache = NemoGuardrails::VerdictCache.new
    calls = 0
    2.times do
      cache.fetch(:input, 'm', 'q') do
        calls += 1
        NemoGuardrails::Verdict.unchecked(rail: :input, reason: 'rail failed')
      end
    end
    assert_equal 2, calls
    assert_equal 0, cache.size
  end

  def test_a_block_is_stored_like_an_allow
    cache = NemoGuardrails::VerdictCache.new
    calls = 0
    2.times do
      cache.fetch(:input, 'm', 'q') do
        calls += 1
        NemoGuardrails::Verdict.block(rail: :input, reason: 'adversarial input')
      end
    end
    assert_equal 1, calls
    assert_equal 'adversarial input', cache.fetch(:input, 'm', 'q') { flunk 'should be cached' }.reason
  end

  def test_the_oldest_entry_is_evicted_at_the_limit
    cache = NemoGuardrails::VerdictCache.new(limit: 2)
    %w[a b c].each { |t| cache.fetch(:input, 'm', t) { allow_verdict } }
    assert_equal 2, cache.size
    calls = 0
    cache.fetch(:input, 'm', 'a') do
      calls += 1
      allow_verdict
    end
    assert_equal 1, calls
  end

  # --- through Rails ---

  def rails_with(content, **kwargs)
    http = StubHTTP.new(responses: { PATH => chat_body(content) })
    backend = NemoGuardrails::GuardModel.new(model: 'test/guard', preset: :apriel_guard, http: http)
    [NemoGuardrails::Rails.new(backend: backend, **kwargs), http]
  end

  def test_rails_memoizes_the_input_rail
    rails, http = rails_with("safe\nnon_adversarial")
    2.times { assert rails.check_input('how do I connect?').allowed? }
    assert_equal 1, http.calls.size
  end

  def test_rails_can_be_built_without_a_cache
    rails, http = rails_with("safe\nnon_adversarial", cache: false)
    2.times { rails.check_input('how do I connect?') }
    assert_equal 2, http.calls.size
    assert_nil rails.cache
  end

  # The guard model reads both turns, so the same answer under a different
  # question has to be judged again.
  def test_the_output_rail_keys_on_the_question_as_well_as_the_answer
    rails, http = rails_with("safe\nnon_adversarial")
    rails.check_output('the same answer', user_input: 'first question')
    rails.check_output('the same answer', user_input: 'second question')
    assert_equal 2, http.calls.size
  end

  def test_env_can_turn_the_cache_off
    saved = ENV.fetch('GUARDRAILS_CACHE', nil)
    ENV['GUARDRAILS_CACHE'] = '0'
    assert_nil NemoGuardrails::Rails.from_env.cache
  ensure
    saved.nil? ? ENV.delete('GUARDRAILS_CACHE') : ENV['GUARDRAILS_CACHE'] = saved
  end

  def test_status_reports_cache_counters
    rails, = rails_with("safe\nnon_adversarial")
    2.times { rails.check_input('q') }
    stats = rails.to_h['cache']
    assert_equal 1, stats['hits']
    assert_equal 1, stats['misses']
  end
end
