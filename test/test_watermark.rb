# frozen_string_literal: true

require_relative 'helper'

# The mark Article 50(2) asks for: machine-readable, detectable by anybody,
# attributable by the issuer, and invisible to the reader.
#
# The fixture is an answer of the shape this desk actually produces, because the
# two failure modes both live in shapes: a mark inside a command, and a mark that
# stops verifying because a mail client rewrapped a paragraph.
class TestWatermark < Minitest::Test
  include GuardrailsTest

  W = Vangrail::Watermark

  KEY = 'a shared secret, not in the repository'
  ISSUER = 'surf/handbook-ask'

  ANSWER = <<~MD
    Your Small Compute grant is 1000 SBU on the CPU nodes, and the balance
    refreshes nightly rather than per job.

    Check what is left with:

    ```bash
    accinfo -p my-project
    ```

    An SBU on a GPU node is not the same unit as an SBU on a CPU node, so read
    the node type beside the number.
  MD

  def marked
    W.mark(ANSWER, key: KEY, issuer: ISSUER)
  end

  # --- the reader sees nothing ---

  def test_the_mark_adds_no_visible_character
    assert_equal ANSWER, W.strip(marked)
  end

  def test_it_adds_only_variation_selectors
    added = marked.each_char.to_a - ANSWER.each_char.to_a

    assert_empty(added.grep_v(/[\u{FE00}-\u{FE0F}\u{E0100}-\u{E01EF}]/))
  end

  # The one that would be a real bug: a selector inside a command is a command
  # that fails in a shell, or runs differently, and a reader copies commands.
  def test_a_fenced_command_comes_back_byte_for_byte
    assert_includes marked, "```bash\naccinfo -p my-project\n```"
  end

  def test_an_indented_block_is_left_alone
    text = "Run the check:\n\n    accinfo -p my-project\n\nThat is the balance.\n"
    result = W.mark(text, key: KEY, issuer: ISSUER)

    assert_includes result, "\n    accinfo -p my-project\n"
  end

  # --- detectable without an agreement with us ---

  def test_anybody_can_tell_the_text_was_generated
    assert W.marked?(marked)
    refute W.marked?(ANSWER)
  end

  def test_the_magic_bytes_are_fixed_and_public
    first = W.marks(marked).first

    assert_equal W::VERSION, first[:version]
    assert_equal W::TAG_BYTES, first[:tag].length
  end

  # --- attributable by the issuer ---

  def test_the_issuer_verifies_and_nobody_else_does
    assert_predicate W.verify(marked, key: KEY, issuer: ISSUER), :authentic?
    refute_predicate W.verify(marked, key: 'the wrong secret', issuer: ISSUER), :authentic?
    refute_predicate W.verify(marked, key: KEY, issuer: 'someone/else'), :authentic?
  end

  # Marked and not ours, which is the answer that keeps the mark honest: a
  # disclosure anybody can copy is not an attribution.
  def test_a_mark_lifted_onto_other_words_does_not_verify
    lifted = "Your grant is 100000 SBU.#{marked[/[\u{FE00}-\u{FE0F}\u{E0100}-\u{E01EF}]+/]}"

    assert W.marked?(lifted)
    refute_predicate W.verify(lifted, key: KEY, issuer: ISSUER), :authentic?
  end

  def test_a_mail_client_that_rewraps_a_paragraph_still_verifies
    rewrapped = marked.sub("1000 SBU on the CPU nodes, and the balance\nrefreshes nightly",
                           "1000 SBU on the CPU nodes,\nand the balance refreshes nightly")

    refute_equal marked, rewrapped
    assert_predicate W.verify(rewrapped, key: KEY, issuer: ISSUER), :authentic?
  end

  def test_one_quoted_paragraph_verifies_on_its_own
    paragraph = marked.split("\n\n").first
    report = W.verify(paragraph, key: KEY, issuer: ISSUER)

    assert_predicate report, :authentic?
    assert_in_delta 1.0, report.coverage
  end

  # Prose marked, code not, so coverage is a share rather than all or nothing.
  def test_coverage_counts_the_segments_it_could_mark
    report = W.verify(marked, key: KEY, issuer: ISSUER)

    assert_operator report.coverage, :>, 0.5
    assert_operator report.coverage, :<, 1.0
  end

  # --- the format ---

  def test_every_byte_value_round_trips
    bytes = (0..255).to_a

    assert_equal([bytes], W.decode(W.encode(bytes)).then { |d| [d.flatten] })
  end

  def test_marking_twice_does_not_stack_selectors
    assert_equal marked, W.mark(marked, key: KEY, issuer: ISSUER)
  end

  def test_without_a_key_it_still_says_the_text_was_generated
    unsigned = W.mark(ANSWER)
    report = W.verify(unsigned, key: KEY, issuer: ISSUER)

    assert_predicate report, :marked?
    refute_predicate report, :authentic?
    assert_equal W::UNSIGNED, W.marks(unsigned).first[:tag]
  end

  def test_empty_and_blank_text_are_not_marked
    refute W.marked?(W.mark('', key: KEY))
    refute W.marked?(W.mark("\n\n   \n", key: KEY))
  end

  # --- the rail ---

  def rail
    Vangrail::Rails::Watermark.new(key: KEY, issuer: ISSUER)
  end

  def test_the_rail_rewrites_the_answer_and_says_which_kind_of_rewrite
    result = rail.call(ANSWER, side: :output)

    assert_predicate result, :modified?
    assert_includes result.categories, 'watermark'
    assert_includes result.categories, 'watermark:signed'
    assert_predicate W.verify(result.content, key: KEY, issuer: ISSUER), :authentic?
  end

  def test_the_rail_reads_answers_and_not_questions
    assert rail.applies_to?(:output)
    refute rail.applies_to?(:input)
    refute rail.applies_to?(:context)
  end

  def test_the_rail_is_offline_and_memoisable
    assert_predicate rail, :offline?
    assert_equal ANSWER, rail.cache_key(ANSWER, side: :output)
  end

  def test_an_unsigned_rail_says_so_in_the_category
    result = Vangrail::Rails::Watermark.new.call(ANSWER, side: :output)

    assert_includes result.categories, 'watermark:unsigned'
    refute_predicate Vangrail::Rails::Watermark.new, :signed?
  end

  def test_a_second_pass_over_a_marked_answer_passes
    once = rail.call(ANSWER, side: :output)

    assert_predicate rail.call(once.content, side: :output), :passed?
  end

  # A stream is checked as it arrives, and the mark is not that kind of check.
  # Marking per chunk would rewrite text already on the reader's screen, once
  # per chunk, each mark covering a different half-finished paragraph.
  def test_the_stream_guard_marks_at_the_end_and_not_per_chunk
    engine = Vangrail::Engine.new(output: [rail])
    guard = Vangrail::StreamGuard.new(engine)

    ANSWER.scan(/.{1,60}/m).each do |chunk|
      verdict = guard.push(chunk)
      refute_predicate verdict, :modified? if verdict
    end

    refute W.marked?(guard.content)

    final = guard.finish

    assert_predicate final, :modified?
    assert_predicate W.verify(final.content, key: KEY, issuer: ISSUER), :authentic?
  end

  def test_a_rail_reads_fragments_unless_it_says_otherwise
    refute_predicate rail, :incremental?
    assert_predicate Vangrail::Rails::Secrets.new, :incremental?
  end

  # The two rails read the same carriers from opposite directions, and this is
  # the order that makes both correct: Obfuscation is input and context, the mark
  # is output. An answer pasted back in as a question loses its mark, which is
  # the right trade in both directions.
  def test_the_inbound_strip_removes_a_mark_and_never_sees_an_answer
    scrubbed = Vangrail::Rails::Obfuscation.scrub(marked)

    refute W.marked?(scrubbed)
    assert_equal ANSWER, scrubbed
    refute Vangrail::Rails::Obfuscation.new(rails: []).applies_to?(:output)
  end

  # The engine builds it by default, because the obligation is not a preference.
  def test_the_builder_puts_it_last_on_the_output_side
    engine = Vangrail::Builder.new({ 'GUARDRAILS_WATERMARK_KEY' => KEY,
                                     'GUARDRAILS_WATERMARK_ISSUER' => ISSUER }).engine

    assert_equal 'watermark', engine.rail_names(:output).last
  end

  def test_naming_a_rail_list_without_it_turns_it_off
    engine = Vangrail::Builder.new({ 'GUARDRAILS_RAILS' => 'input,context,output' }).engine

    refute_includes engine.rail_names(:output), 'watermark'
  end
end
