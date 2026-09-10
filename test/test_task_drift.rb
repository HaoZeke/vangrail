# frozen_string_literal: true

require_relative 'helper'

# What the model says it was asked, before and after the document.
class TestTaskDrift < Minitest::Test
  PATH = '/chat/completions'

  # Answers the baseline call and the document call separately, in that order,
  # which is the order the rail makes them in.
  def rail_for(*replies)
    queue = replies.dup
    http = StubHTTP.new(responses: { PATH => ->(_payload, _n) { chat_body(queue.shift || queue.last) } })
    chat = Vangrail::Chat.new(model: 'test/model', http: http)
    [Vangrail::Rails::TaskDrift.new(chat: chat, model: 'test/judge'), http]
  end

  def call(rail, document: 'a manual page', question: 'How do I use tar?')
    rail.call(document, side: :context, user_input: question)
  end

  def test_a_request_that_appears_only_beside_the_document_blocks
    rail, = rail_for("How to use tar\n", "How to use tar\nAnalyse electric car sales\n")
    result = call(rail)

    assert_predicate result, :blocked?
    assert_equal ['task_drift'], result.categories
    assert_includes result.reason, 'Analyse electric car sales'
  end

  def test_the_same_requests_in_other_words_are_not_drift
    rail, = rail_for("Explain how to use tar\n", "Describe using tar archives\n")

    assert_predicate call(rail), :passed?
  end

  def test_a_document_that_adds_nothing_passes
    rail, = rail_for("How to use tar\n", "How to use tar\n")

    assert_predicate call(rail), :passed?
  end

  def test_a_document_the_model_reports_nothing_for_passes
    rail, = rail_for("How to use tar\n", "NONE\n")

    assert_predicate call(rail), :passed?
  end

  # The probe's own instruction is a request the model received, so it lists it
  # about half the time. It is in both prompts and the comparison usually
  # cancels it; usually is not good enough when the cost is a false alarm on a
  # clean page.
  def test_the_probe_s_own_instruction_is_never_counted_as_drift
    rail, = rail_for("How to use tar\n",
                     "How to use tar\nComplete the given sentence\n" \
                     "All requests that I am going to execute now are:\n")

    assert_predicate call(rail), :passed?
  end

  # A model that answers the question instead of listing it pollutes the
  # baseline until every later line looks familiar, which is how the first
  # version of this passed a document carrying a socket.
  def test_the_model_answering_instead_of_listing_is_not_read_as_requests
    prose = "How to use tar\n| Goal | Command |\n|---|---|\n```\ntar -cvf a.tar x\n```\n" \
            "tar is a command-line utility for creating, listing and extracting archive files\n"
    rail, = rail_for(prose, "#{prose}Analyse electric car sales\n")
    result = call(rail)

    assert_predicate result, :blocked?
    assert_includes result.reason, 'Analyse electric car sales'
    refute_includes result.reason, 'Goal'
  end

  def test_a_document_with_no_question_is_unchecked
    rail, http = rail_for("How to use tar\n")
    result = rail.call('a page', side: :context)

    assert_predicate result, :passed?
    refute_predicate result, :certain?
    assert_nil http.last_payload
  end

  def test_an_unreadable_baseline_is_unchecked
    rail, = rail_for("```\n", "How to use tar\nAnalyse electric car sales\n")
    result = call(rail)

    assert_predicate result, :passed?
    refute_predicate result, :certain?
  end

  # A caller screening six passages for one question should pay for the
  # baseline once, so it can be supplied.
  def test_a_supplied_baseline_replaces_the_first_call
    rail, http = rail_for("How to use tar\n")
    baseline = [{ text: 'How to use tar', words: %w[tar] }]
    result = rail.call('a page', side: :context, user_input: 'How do I use tar?', baseline: baseline)

    assert_predicate result, :passed?
    assert_equal 1, http.calls.count { |c| c[:method] == :post }
  end

  def test_the_probe_does_not_fence_the_document
    rail, http = rail_for("How to use tar\n", "How to use tar\n")
    call(rail, document: 'the page body')
    sent = http.last_payload['messages'].last['content']

    assert_includes sent, 'the page body'
    refute_includes sent, 'DOCUMENT>>>'
    assert_includes sent, 'All requests that I am going to execute now are'
  end

  def test_it_reads_documents_and_says_it_needs_a_network
    rail, = rail_for('NONE')

    assert_equal [:context], rail.sides
    refute_predicate rail, :offline?
  end

  def test_it_refuses_to_build_without_a_model
    assert_raises(ArgumentError) { Vangrail::Rails::TaskDrift.new }
  end
end
