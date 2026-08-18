# frozen_string_literal: true

require_relative 'helper'

# Rails that run while the answer is still arriving.
#
# The thing being tested is a timing property, not a decision: the same rails
# reach the same verdicts either way, but a stream guard reaches them before the
# text is on screen rather than after.
class TestStreamGuard < Minitest::Test
  SECRET = 'sk-abcdefghijklmnopqrstuvwx1234'

  def engine(rails = [Vangrail::Rails::Secrets.new])
    Vangrail::Engine.new(output: rails)
  end

  # Feeds text in small pieces, the way a token stream arrives.
  def stream(guard, text, size: 12)
    seen = []
    text.chars.each_slice(size) do |slice|
      result = guard.push(slice.join)
      seen << result if result
      break if result&.blocked?
    end
    seen
  end

  def test_nothing_to_report_while_the_text_is_clean
    guard = Vangrail::StreamGuard.new(engine)
    events = stream(guard, 'Submit the job with sbatch and watch it with squeue. ' * 3)

    assert_empty events.compact
    assert_predicate guard.finish, :passed?
  end

  # The point of the class. A credential that appears for four seconds has
  # appeared, so the rewrite has to happen before the chunk is shown.
  def test_a_credential_is_caught_before_the_stream_ends
    guard = Vangrail::StreamGuard.new(engine)
    text = "Set the key in your config: api_key=#{SECRET} and then run sbatch. " \
           'The rest of this answer keeps going for a while afterwards. ' * 3
    events = stream(guard, text)

    refute_empty events, 'nothing was reported mid-stream'
    assert(events.any?(&:modified?), 'the credential was not caught until finish')
    refute_includes guard.content, SECRET
  end

  def test_a_blocking_rail_stops_the_stream_at_the_chunk_that_crossed_the_line
    pattern = Vangrail::Rails::Pattern.new(patterns: { 'forbidden' => /forbidden phrase/ },
                                           sides: [:output])
    guard = Vangrail::StreamGuard.new(engine([pattern]))
    tail = 'this text should never be inspected because the stream stopped. ' * 5
    stream(guard, "A normal opening sentence. Then a forbidden phrase appears. #{tail}")

    assert_predicate guard, :blocked?
    assert_operator guard.content.length, :<, 200, 'the guard kept consuming after blocking'
  end

  def test_a_blocked_guard_ignores_everything_after
    pattern = Vangrail::Rails::Pattern.new(patterns: { 'nope' => /nope/ }, sides: [:output])
    guard = Vangrail::StreamGuard.new(engine([pattern]))
    stream(guard, "a nope arrives here and the guard stops#{' padding' * 10}")
    before = guard.content

    again = guard.push('more text that should be ignored entirely')

    assert_predicate again, :blocked?
    assert_equal before, guard.content
  end

  # --- what it deliberately does not do ---

  # A model rail costs a round trip. Running one every few tokens turns a two
  # second answer into a minute, so they wait for the end.
  def test_model_backed_rails_do_not_run_per_chunk
    http = StubHTTP.new(responses: { '/chat/completions' => chat_body('{"violation": 0}') })
    chat = Vangrail::Chat.new(model: 'm', http: http)
    judge = Vangrail::Rails::SelfCheck.new(chat: chat, model: 'm', sides: [:output])

    guard = Vangrail::StreamGuard.new(engine([judge]))
    stream(guard, 'a long answer that arrives in many small pieces over time. ' * 4)

    assert_empty http.calls, 'a model rail ran mid-stream'

    guard.finish

    assert_equal 1, http.calls.size, 'the model rail did not run at the end'
  end

  # Half a sentence is not the object a grounding rail was written to judge:
  # its citation has not been generated yet.
  def test_a_partial_answer_is_not_judged_by_a_model_rail
    http = StubHTTP.new(responses: { '/chat/completions' => chat_body('{"violation": 1}') })
    chat = Vangrail::Chat.new(model: 'm', http: http)
    grounding = Vangrail::Rails::Grounding.new(chat: chat, model: 'm')

    guard = Vangrail::StreamGuard.new(engine([grounding]), passages: [{ 'text' => 'Use gpu_a100.' }])
    events = stream(guard, 'Use gpu_h200 for the job. ' * 4)

    assert_empty events.compact, 'the grounding rail ran on a partial answer'
    assert_predicate guard.finish, :blocked?, 'the grounding rail did not run at the end'
  end

  # --- bookkeeping ---

  def test_the_check_interval_is_respected
    guard = Vangrail::StreamGuard.new(engine, interval: 100)
    stream(guard, 'x' * 250, size: 10)

    assert_operator guard.checks, :<=, 3
    assert_operator guard.checks, :>=, 2
  end

  def test_an_empty_chunk_changes_nothing
    guard = Vangrail::StreamGuard.new(engine)

    assert_nil guard.push('')
    assert_nil guard.push(nil)
    assert_equal '', guard.content
  end

  def test_finish_reports_the_rewrite_it_made
    guard = Vangrail::StreamGuard.new(engine)
    guard.push("here is a token #{SECRET} in the answer")
    result = guard.finish

    assert_predicate result, :allowed?
    refute_includes guard.content, SECRET
  end

  # The emit path. A caller that prints result.content reprints the whole
  # buffer after every rewrite. take hands out only the suffix that has not
  # been shown, so a redaction in the latest chunk does not replay the prefix.
  def test_take_hands_out_only_what_has_not_been_shown
    guard = Vangrail::StreamGuard.new(engine, interval: 6)
    guard.push('hello ')

    assert_equal 'hello ', guard.take
    guard.push('world!')

    assert_equal 'world!', guard.take
    assert_equal '', guard.take
  end

  # The guarantee, and the reason take is not simply the buffer.
  #
  # Found by wiring this into an application: with a long interval the guard
  # handed out the tail that no rail had read yet, so a credential reached the
  # screen and was redacted a chunk later. Text waits until a check covers it.
  def test_nothing_is_handed_out_before_a_rail_has_read_it
    guard = Vangrail::StreamGuard.new(engine, interval: 10_000)
    guard.push("Put api_key=#{SECRET} in the file.")

    assert_equal '', guard.take, 'uninspected text was released'
    assert_equal 0, guard.checked

    guard.finish
    released = guard.take

    refute_empty released
    refute_includes released, SECRET
  end

  # The cost of that guarantee, stated: the tail lags by up to one interval.
  def test_the_unchecked_tail_lags_by_at_most_one_interval
    guard = Vangrail::StreamGuard.new(engine, interval: 20)
    guard.push('a' * 25)
    guard.take
    guard.push('b' * 5)

    assert_equal '', guard.take
    assert_equal guard.checked, guard.content.length
  end

  def test_content_is_the_checked_prefix
    guard = Vangrail::StreamGuard.new(engine, interval: 10_000)
    guard.push("Put api_key=#{SECRET} in the file.")

    assert_equal '', guard.content
    assert_equal 0, guard.checked
    refute_respond_to guard, :buffer
  end

  def test_take_after_a_redaction_does_not_reprint_the_clean_prefix
    guard = Vangrail::StreamGuard.new(engine, interval: 1)
    prefix = 'Set the key in your config: '
    guard.push(prefix)

    assert_equal prefix, guard.take

    guard.push("api_key=#{SECRET} then submit with sbatch. #{'padding ' * 8}")
    delta = guard.take

    refute_includes delta, SECRET
    refute_includes delta, prefix.rstrip
    refute_includes guard.content, SECRET
    assert_includes guard.content, prefix
  end

  def test_an_engine_with_no_output_rails_says_nothing_and_finishes_unchecked
    guard = Vangrail::StreamGuard.new(Vangrail::Engine.new)

    assert_empty stream(guard, 'anything at all, at some length, arriving in pieces. ' * 2).compact
    result = guard.finish

    assert_predicate result, :passed?
    refute_predicate result, :certain?
  end

  # A rewrite hands back a string the rail may still own, and this class appends
  # to its buffer in place. With a memoized rail the same Result goes to the next
  # caller with the same text, so an append after `finish` wrote one turn's
  # tokens into another turn's cached answer: text from a different reader,
  # served as an answer, with nothing in the log to suggest it.
  #
  # Reachable rather than theoretical: one push after finish, or one guard
  # reused for a second answer.
  def test_a_push_after_finish_cannot_reach_a_cached_answer
    cache = Vangrail::ResultCache.new
    engine = Vangrail::Engine.new(
      output: [Vangrail::Rails::Watermark.new(key: 'k', issuer: 'issuer')],
      cache: cache
    )
    answer = "The limit is 1000 SBU per project.\n"

    guard = Vangrail::StreamGuard.new(engine)
    guard.push(answer)
    finished = guard.finish.content.dup
    guard.push('and one more sentence.')

    again = engine.check_output(answer)

    assert_equal 1, cache.hits, 'the second check did not come from the cache, so this proves nothing'
    assert_equal finished, again.content
    refute_includes again.content, 'one more sentence'
  end

  # The other half, so a future caller that mutates a shared rewrite fails where
  # it wrote rather than three hundred requests later.
  def test_a_cached_rewrite_is_not_writable
    cache = Vangrail::ResultCache.new
    engine = Vangrail::Engine.new(
      output: [Vangrail::Rails::Watermark.new(key: 'k', issuer: 'issuer')],
      cache: cache
    )
    result = engine.check_output('Answers are marked in this deployment.')

    assert_predicate result, :modified?
    assert_raises(FrozenError) { result.content << ' appended by a careless caller' }
  end
end
