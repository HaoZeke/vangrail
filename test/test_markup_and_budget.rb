# frozen_string_literal: true

require_relative 'helper'

# Markup that does something when rendered, and text too large to be a question.
class TestMarkup < Minitest::Test
  include GuardrailsTest

  def rail
    @rail ||= Vangrail::Rails::Markup.new
  end

  def check(text)
    rail.call(text, side: :output)
  end

  def test_a_script_tag_in_an_answer_is_removed
    result = check('Submit with sbatch. [1]<script>fetch("https://x.example.net")</script>')

    assert_predicate result, :modified?
    assert_includes result.categories, 'script'
    refute_includes result.content, '<script'
    assert_includes result.content, 'Submit with sbatch. [1]'
  end

  def test_the_lone_image_exploit_is_defanged
    result = check('See the diagram. <img src=x onerror="fetch(\'//x.example.net\')">')

    assert_predicate result, :modified?
    assert_includes result.categories, 'event_handler'
    refute_includes result.content, 'onerror'
  end

  def test_the_other_carriers_are_covered
    {
      'frame' => '<iframe src="https://x.example.net"></iframe>',
      'active_scheme' => '<a href="javascript:alert(1)">click</a>',
      'meta_refresh' => '<meta http-equiv="refresh" content="0;url=https://x.example.net">',
      'base_tag' => '<base href="https://x.example.net/">',
      'form' => '<form action="https://x.example.net"><input name="q"></form>',
      'style_block' => '<style>body{display:none}</style>',
    }.each do |label, markup|
      result = check("An answer. [1] #{markup}")

      assert_predicate result, :modified?, label
      assert_includes result.categories, label
    end
  end

  # A handbook answer is commands, paths, flags, and citation markers.
  BENIGN = [
    'Submit with `sbatch job.sh` [1] and watch it with `squeue -u $USER` [1].',
    "```bash\n#SBATCH --time=24:00:00\n#SBATCH --mem=64G\n```\nThat is the form. [2]",
    'Compare a < b and c > d in your filter expression. [1]',
    'The path is /gpfs/work/project and the mode is 0750. [2]',
    'Use --array=1-10 with %5 to limit concurrency. [1]',
  ].freeze

  def test_ordinary_answers_are_untouched
    flagged = BENIGN.reject { |t| check(t).passed? }

    assert_empty flagged, "flagged:\n  #{flagged.join("\n  ")}"
  end

  def test_it_rewrites_rather_than_refusing
    result = check('Answer. <script>x()</script>')

    assert_predicate result, :allowed?
    refute_predicate result, :blocked?
  end

  def test_it_reads_answers_only
    r = rail

    assert r.applies_to?(:output)
    refute r.applies_to?(:input)
    assert_predicate r, :offline?
  end
end

# Size, which is the one attack that costs the operator directly.
class TestBudget < Minitest::Test
  include GuardrailsTest

  def rail(**kwargs)
    Vangrail::Rails::Budget.new(**kwargs)
  end

  def test_an_ordinary_question_passes
    assert_predicate rail.call('How do I submit a GPU job?', side: :input), :passed?
  end

  def test_a_pasted_megabyte_is_refused
    result = rail.call('x' * 20_000, side: :input)

    assert_predicate result, :blocked?
    assert_includes result.categories, 'over_budget'
    assert_includes result.reason, '8000 allowed'
  end

  # Retrieved pages are legitimately longer than anything a reader types.
  def test_documents_get_their_own_larger_limit
    page = 'x' * 20_000

    assert_predicate rail.call(page, side: :context), :passed?
    assert_predicate rail.call('x' * 70_000, side: :context), :blocked?
  end

  def test_either_side_can_be_turned_off
    assert_predicate rail(max_context: nil).call('x' * 500_000, side: :context), :passed?
    assert_predicate rail(max_characters: nil).call('x' * 500_000, side: :input), :passed?
  end

  # Blocking rather than truncating: a truncated question is a different
  # question, and answering that well is worse than saying the box has a limit.
  def test_it_does_not_truncate
    result = rail.call('x' * 20_000, side: :input)

    refute_predicate result, :modified?
    assert_nil result.content
  end

  def test_the_limit_moves
    assert_predicate rail(max_characters: 20).call('a question that is longer than twenty', side: :input), :blocked?
  end

  def test_it_is_offline_and_memoized_on_the_size
    r = rail

    assert_predicate r, :offline?
    assert_equal 'input:5', r.cache_key('12345', side: :input)
  end
end
