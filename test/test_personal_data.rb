# frozen_string_literal: true

require_relative 'helper'

# A privacy rail, and the login examples it must not eat.
class TestPersonalData < Minitest::Test
  include GuardrailsTest

  def rail
    @rail ||= Vangrail::Rails::PersonalData.new
  end

  def check(text)
    rail.call(text, side: :input)
  end

  def test_a_mailbox_is_redacted
    result = check('My colleague r.jansen@example.org cannot log in either.')

    assert_predicate result, :modified?
    assert_includes result.categories, 'email'
    refute_includes result.content, 'r.jansen@example.org'
    assert_includes result.content, 'cannot log in either'
  end

  def test_a_phone_number_is_redacted
    assert_predicate check('Call me on +31 6 12345678 if the job fails.'), :modified?
    assert_predicate check('My desk line is 070 123 4567.'), :modified?
  end

  def test_an_iban_is_redacted
    assert_predicate check('The invoice went to NL91 ABNA 0417 1643 00 last month.'), :modified?
  end

  def test_a_card_number_is_redacted_and_a_long_id_is_not
    assert_predicate check('I paid with 4111 1111 1111 1111 for the workshop.'), :modified?
    assert_predicate check('Job 4111111111111112 is still pending.'), :passed?
  end

  # --- the traps ---

  # The most common string on a cluster desk. Redacting it destroys the answer
  # to the most commonly asked question there is.
  LOGIN_EXAMPLES = [
    'How do I ssh rgoswami@snellius.example.org from my laptop?',
    'scp results.tar rgoswami@snellius.example.org:/scratch/ fails with permission denied.',
    'Use `rsync -a data/ rgoswami@snellius.example.org:/project/` to copy it up.',
    'My ~/.ssh/config has Host snel with User rgoswami@snellius.example.org, is that wrong?',
    'The docs say to run ssh-copy-id rgoswami@snellius.example.org first.',
  ].freeze

  def test_login_targets_survive
    eaten = LOGIN_EXAMPLES.reject { |t| check(t).passed? }

    assert_empty eaten, "redacted a login example:\n  #{eaten.join("\n  ")}"
  end

  def test_anything_inside_backticks_survives
    text = 'Is `user@host.example.org` the right form, or should I write it differently?'

    assert_predicate check(text), :passed?
  end

  def test_a_fenced_block_survives
    text = "Here is my config:\n\n```\nHost snel\n  User someone@example.org\n```\n\nWhat is wrong?"

    assert_predicate check(text), :passed?
  end

  def test_a_documentation_placeholder_is_not_a_person
    ['Do I write user@example.org or my real address?',
     'The manual shows username@example.org in the ssh line.'].each do |text|
      assert_predicate check(text), :passed?, text
    end
  end

  # Ordinary handbook traffic, full of long numbers.
  BENIGN = [
    'Job 12345678 was cancelled due to the time limit.',
    'My allocation is 250000 SBU and I have used 180000.',
    'The node has 128 cores and 512 GB of memory.',
    'Set --time=24:00:00 and --mem=64G in the script.',
    'The checksum is 8f14e45fceea167a5a36dedd4bea2543.',
    'I requested 4 nodes and got 2, why?',
  ].freeze

  def test_ordinary_questions_are_untouched
    flagged = BENIGN.reject { |t| check(t).passed? }

    assert_empty flagged, "flagged:\n  #{flagged.join("\n  ")}"
  end

  # --- the Dutch identifier, which is the label and the checksum together ---

  # The number nobody should paste into a support question, in the words a
  # Dutch reader writes it with.
  def test_a_labelled_bsn_is_redacted
    %w[BSN burgerservicenummer sofinummer].each do |label|
      result = check("Mijn #{label} is 123456782, kunt u mijn account koppelen?")

      assert_predicate result, :modified?, "missed a labelled #{label}"
      refute_includes result.content, '123456782'
      # The label survives, so the desk still knows what it was told about.
      assert_includes result.content.downcase, label.downcase
    end
  end

  def test_a_bsn_printed_with_separators_is_still_redacted
    result = check('Sofinummer: 123.456.782 hoort bij deze aanvraag.')

    assert_predicate result, :modified?
    refute_includes result.content, '123.456.782'
  end

  # The reason bare nine-digit runs are not matched at all. This one passes the
  # elfproef, and it is a job id.
  def test_a_bare_number_that_passes_the_checksum_is_left_alone
    ['Job 123456782 failed with an OOM after four hours.',
     'The allocation number is 123456782 for this project.',
     'Taak 123456782 is gestopt vanwege de tijdslimiet.'].each do |text|
      assert_predicate check(text), :passed?, "redacted a number that was not identified as a BSN: #{text}"
    end
  end

  def test_a_labelled_number_that_fails_the_checksum_is_left_alone
    assert_predicate check('My BSN is 123456789, he wrote, which does not check out.'), :passed?
  end

  # Nine identical digits satisfy the arithmetic and are a form's placeholder.
  def test_a_placeholder_run_is_not_a_person
    assert_predicate check('bsn 000000000 is what the form prints when it is empty'), :passed?
  end

  # --- bookkeeping ---

  def test_it_reads_questions_by_default
    r = rail

    assert r.applies_to?(:input)
    refute r.applies_to?(:output)
    assert_predicate r, :offline?
    assert_equal 'text', r.cache_key('text', side: :input)
  end

  def test_it_rewrites_rather_than_refusing
    result = check('Email me at someone@example.org with the answer.')

    assert_predicate result, :modified?
    refute_predicate result, :blocked?
    assert_predicate result, :allowed?
  end
end
