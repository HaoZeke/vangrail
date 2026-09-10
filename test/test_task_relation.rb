# frozen_string_literal: true

require_relative 'helper'

# The relation between a document and the question it was retrieved for, driven
# against a recorded HTTP double.
class TestTaskRelation < Minitest::Test
  PATH = '/chat/completions'

  def rail_for(content)
    http = StubHTTP.new(responses: { PATH => chat_body(content) })
    chat = Vangrail::Chat.new(model: 'test/model', http: http)
    [Vangrail::Rails::TaskRelation.new(chat: chat, model: 'test/judge'), http]
  end

  def verdict(tasks, parent: 'use tar', injected: nil)
    injected = tasks.any? { |task| task['relation'] == 'unrelated' } if injected.nil?
    JSON.generate('parent' => parent, 'tasks' => tasks, 'injected' => injected)
  end

  def test_an_unrelated_task_in_a_document_blocks_and_names_it
    rail, = rail_for(verdict([{ 'task' => 'archive files', 'relation' => 'related' },
                              { 'task' => 'rename files with date', 'relation' => 'unrelated' }]))
    result = rail.call('a manual page with a sentence in it', side: :context, user_input: 'How do I use tar?')

    assert_predicate result, :blocked?
    assert_equal ['off_task_instruction'], result.categories
    assert_includes result.reason, 'rename files with date'
    assert_includes result.reason, 'use tar'
  end

  def test_a_document_whose_tasks_all_serve_the_question_passes
    rail, = rail_for(verdict([{ 'task' => 'archive files', 'relation' => 'related' },
                              { 'task' => 'extract an archive', 'relation' => 'related' }]))

    assert_predicate rail.call('a manual page', side: :context, user_input: 'How do I use tar?'), :passed?
  end

  def test_a_document_that_asks_for_nothing_passes
    rail, = rail_for(verdict([]))

    assert_predicate rail.call('prose with no request in it', side: :context, user_input: 'How do I use tar?'), :passed?
  end

  # The labels carry the reason and the flag does not, so a model that sets the
  # flag while calling every task related has contradicted itself and the labels
  # are what the rail acts on. This is the direction that matters: the flag
  # alone would block a page no task was found wrong in.
  def test_the_labels_decide_rather_than_the_flag
    rail, = rail_for(verdict([{ 'task' => 'archive files', 'relation' => 'related' }], injected: true))

    assert_predicate rail.call('a manual page', side: :context, user_input: 'How do I use tar?'), :passed?
  end

  # Every unparsed answer is a check that did not happen, and this rail is the
  # one most likely to meet a model that cannot hold a JSON contract: the paper
  # it implements reports the summariser's false-alarm rate moving by two orders
  # of magnitude between models.
  def test_an_answer_in_the_wrong_shape_is_unchecked_rather_than_clean
    ['not JSON at all', '{"parent": "use tar"}', '{"parent": "x", "tasks": [{"task": "y"}]}',
     '{"parent": "x", "tasks": [{"task": "y", "relation": "maybe"}]}'].each do |body|
      rail, = rail_for(body)
      result = rail.call('a page', side: :context, user_input: 'How do I use tar?')

      assert_predicate result, :passed?
      refute_predicate result, :certain?
    end
  end

  def test_a_fenced_verdict_is_read
    rail, = rail_for("```json\n#{verdict([{ 'task' => 'send credentials', 'relation' => 'unrelated' }])}\n```")

    assert_predicate rail.call('a page', side: :context, user_input: 'How do I use tar?'), :blocked?
  end

  # Without a question there is no task to be unrelated to. Inventing a parent
  # from the document would make every document self-consistent, which is the
  # one answer this rail must never give.
  def test_a_document_with_no_question_is_unchecked
    rail, http = rail_for(verdict([]))
    result = rail.call('a page', side: :context)

    assert_predicate result, :passed?
    refute_predicate result, :certain?
    assert_nil http.last_payload, 'the endpoint was called with nothing to compare against'
  end

  # Jia et al.'s condition is contribution to at least one user-level
  # instruction, not to the newest one. A rail comparing against the current
  # turn alone calls a page serving the question before it an injection, which
  # in a dialogue is most pages.
  def test_every_user_goal_in_the_dialogue_is_a_parent
    rail, http = rail_for(verdict([]))
    history = [{ role: :user, text: 'How do I use tar?' },
               { role: :assistant, text: 'tar creates archives.' },
               { role: :user, text: 'And how do I compress it?' }]
    rail.call('a page', side: :context, user_input: 'What about gzip?', history: history)
    sent = http.last_payload['messages'].last['content']

    assert_includes sent, 'How do I use tar?'
    assert_includes sent, 'And how do I compress it?'
    assert_includes sent, 'What about gzip?'
    refute_includes sent, 'tar creates archives.'
  end

  def test_the_cache_key_covers_the_whole_dialogue
    rail, = rail_for(verdict([]))
    one = { user_input: 'What about gzip?', history: [{ role: :user, text: 'How do I use tar?' }] }
    two = { user_input: 'What about gzip?', history: [{ role: :user, text: 'How do I use rsync?' }] }

    refute_equal rail.cache_key('the same page', one), rail.cache_key('the same page', two)
  end

  def test_the_question_and_the_document_both_reach_the_model
    rail, http = rail_for(verdict([]))
    rail.call('the page body', side: :context, user_input: 'How do I use tar?')
    messages = http.last_payload['messages']

    assert_equal 'system', messages.first['role']
    assert_includes messages.first['content'], 'task summariser'
    assert_includes messages.last['content'], 'How do I use tar?'
    assert_includes messages.last['content'], 'the page body'
  end

  # A cached verdict is about the pair. The same page under a different question
  # is a different question, and a rail that cached on the page alone would
  # answer the second one with the first one's verdict.
  def test_the_cache_key_covers_both_sides
    rail, = rail_for(verdict([]))
    page = 'the same page'

    refute_equal rail.cache_key(page, { user_input: 'How do I use tar?' }),
                 rail.cache_key(page, { user_input: 'How do I use rsync?' })
  end

  def test_it_reads_documents_and_says_it_needs_a_network
    rail, = rail_for(verdict([]))

    assert_equal [:context], rail.sides
    refute_predicate rail, :offline?
  end

  def test_it_refuses_to_build_without_a_model
    assert_raises(ArgumentError) { Vangrail::Rails::TaskRelation.new }
  end
end
