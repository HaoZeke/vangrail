# frozen_string_literal: true

require_relative 'helper'

# The three statuses, and the memo's two refusals.
class TestResult < Minitest::Test
  R = Vangrail::Result

  def test_the_three_statuses_answer_consistently
    passed = R.passed(rail: 'a')

    assert_predicate passed, :passed?
    assert_predicate passed, :allowed?
    refute_predicate passed, :blocked?

    modified = R.modified(rail: 'a', content: 'edited')

    assert_predicate modified, :modified?
    assert_predicate modified, :allowed?
    refute_predicate modified, :blocked?

    blocked = R.blocked(rail: 'a')

    assert_predicate blocked, :blocked?
    refute_predicate blocked, :allowed?
  end

  def test_content_or_returns_the_rewrite_only_when_there_is_one
    assert_equal 'edited', R.modified(rail: 'a', content: 'edited').content_or('original')
    assert_equal 'original', R.passed(rail: 'a').content_or('original')
    assert_equal 'original', R.modified(rail: 'a', content: nil).content_or('original')
  end

  def test_unchecked_is_allowed_and_not_certain
    result = R.unchecked(rail: 'a', reason: 'nothing ran')

    assert_predicate result, :passed?
    refute_predicate result, :certain?
    assert_equal 'nothing ran', result.reason
  end

  def test_with_rail_renames_without_changing_the_decision
    renamed = R.blocked(rail: 'inner', reason: 'why').with_rail('outer')

    assert_equal 'outer', renamed.rail
    assert_predicate renamed, :blocked?
    assert_equal 'why', renamed.reason
  end

  def test_an_unknown_status_raises
    assert_raises(ArgumentError) { R.new(status: :probably_fine, rail: 'a') }
  end

  def test_to_h_omits_what_is_absent
    h = R.passed(rail: 'a').to_h

    assert_equal 'passed', h['status']
    refute h.key?('categories')
    refute h.key?('reason')
  end

  # --- the memo ---

  def cache
    Vangrail::ResultCache.new
  end

  def test_a_repeat_does_not_reach_the_block
    memo = cache
    calls = 0
    2.times do
      memo.fetch(:input, 'model', 'same text') do
        calls += 1
        R.passed(rail: 'a')
      end
    end

    assert_equal 1, calls
    assert_equal 1, memo.hits
  end

  def test_rail_and_model_are_part_of_the_key
    memo = cache
    memo.fetch(:input, 'model-a', 'text') { R.passed(rail: 'a') }
    memo.fetch(:input, 'model-b', 'text') { R.passed(rail: 'a') }
    memo.fetch(:output, 'model-a', 'text') { R.passed(rail: 'a') }

    assert_equal 3, memo.misses
  end

  # An uncertain result records a rail that failed or did not run. Caching it
  # would turn one unlucky moment into a session-long hole.
  def test_an_uncertain_result_is_never_stored
    memo = cache
    calls = 0
    2.times do
      memo.fetch(:input, 'm', 'text') do
        calls += 1
        R.unchecked(rail: 'a', reason: 'rail failed')
      end
    end

    assert_equal 2, calls
    assert_equal 0, memo.size
  end

  def test_the_oldest_entry_goes_first
    memo = Vangrail::ResultCache.new(limit: 2)
    %w[a b c].each { |t| memo.fetch(:input, 'm', t) { R.passed(rail: 'x') } }

    assert_equal 2, memo.size
    calls = 0
    memo.fetch(:input, 'm', 'a') do
      calls += 1
      R.passed(rail: 'x')
    end

    assert_equal 1, calls
  end

  # --- through the engine ---

  def test_the_engine_memoizes_a_rail_that_offers_a_key
    rail = GuardrailsTest::ScriptedRail.new(R.passed(rail: 'p'), name: 'p')
    def rail.cache_key(text, _context) = text
    engine = Vangrail::Engine.new(input: [rail])
    2.times { engine.check_input('same question') }

    assert_equal 1, rail.seen.size
  end

  # The memo keys Rail.usable(text). A NUL is valid UTF-8; a broken byte
  # is not. Tagging the same bytes ASCII-8BIT must not be a second slot.
  def test_the_engine_keys_the_memo_on_usable_text
    rail = GuardrailsTest::ScriptedRail.new(R.passed(rail: 'p'), name: 'p')
    def rail.cache_key(text, _context) = text
    engine = Vangrail::Engine.new(input: [rail])
    raw = "same\x00question\xC3"
    engine.check_input(raw.dup.force_encoding(Encoding::UTF_8))
    engine.check_input(raw.dup.force_encoding(Encoding::ASCII_8BIT))

    assert_equal 1, rail.seen.size
    assert_equal 1, engine.cache.hits
  end

  # A rail whose decision depends on more than the text says so with a nil key,
  # and the engine must respect that rather than guessing.
  def test_the_engine_never_memoizes_a_rail_without_a_key
    rail = GuardrailsTest::ScriptedRail.new(R.passed(rail: 'p'), name: 'p')
    def rail.cache_key(_text, _context) = nil
    engine = Vangrail::Engine.new(input: [rail])
    2.times { engine.check_input('same question') }

    assert_equal 2, rail.seen.size
  end

  def test_an_engine_can_be_built_without_a_memo
    engine = Vangrail::Engine.new(cache: false)

    assert_nil engine.cache
  end
end
