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

    assert result.modified?
    assert_includes result.categories, 'email'
    refute_includes result.content, 'r.jansen@example.org'
    assert_includes result.content, 'cannot log in either'
  end

  def test_a_phone_number_is_redacted
    assert check('Call me on +31 6 12345678 if the job fails.').modified?
    assert check('My desk line is 070 123 4567.').modified?
  end

  def test_an_iban_is_redacted
    assert check('The invoice went to NL91 ABNA 0417 1643 00 last month.').modified?
  end

  def test_a_card_number_is_redacted_and_a_long_id_is_not
    assert check('I paid with 4111 1111 1111 1111 for the workshop.').modified?
    assert check('Job 4111111111111112 is still pending.').passed?
  end

  # --- the traps ---

  # The most common string on a cluster desk. Redacting it destroys the answer
  # to the most commonly asked question there is.
  LOGIN_EXAMPLES = [
    'How do I ssh rgoswami@snellius.example.org from my laptop?',
    'scp results.tar rgoswami@snellius.example.org:/scratch/ fails with permission denied.',
    'Use `rsync -a data/ rgoswami@snellius.example.org:/project/` to copy it up.',
    'My ~/.ssh/config has Host snel with User rgoswami@snellius.example.org, is that wrong?',
    'The docs say to run ssh-copy-id rgoswami@snellius.example.org first.'
  ].freeze

  def test_login_targets_survive
    eaten = LOGIN_EXAMPLES.reject { |t| check(t).passed? }
    assert_empty eaten, "redacted a login example:\n  #{eaten.join("\n  ")}"
  end

  def test_anything_inside_backticks_survives
    text = 'Is `user@host.example.org` the right form, or should I write it differently?'
    assert check(text).passed?
  end

  def test_a_fenced_block_survives
    text = "Here is my config:\n\n```\nHost snel\n  User someone@example.org\n```\n\nWhat is wrong?"
    assert check(text).passed?
  end

  def test_a_documentation_placeholder_is_not_a_person
    ['Do I write user@example.org or my real address?',
     'The manual shows username@example.org in the ssh line.'].each do |text|
      assert check(text).passed?, text
    end
  end

  # Ordinary handbook traffic, full of long numbers.
  BENIGN = [
    'Job 12345678 was cancelled due to the time limit.',
    'My allocation is 250000 SBU and I have used 180000.',
    'The node has 128 cores and 512 GB of memory.',
    'Set --time=24:00:00 and --mem=64G in the script.',
    'The checksum is 8f14e45fceea167a5a36dedd4bea2543.',
    'I requested 4 nodes and got 2, why?'
  ].freeze

  def test_ordinary_questions_are_untouched
    flagged = BENIGN.reject { |t| check(t).passed? }
    assert_empty flagged, "flagged:\n  #{flagged.join("\n  ")}"
  end

  # --- bookkeeping ---

  def test_it_reads_questions_by_default
    r = rail
    assert r.applies_to?(:input)
    refute r.applies_to?(:output)
    assert r.offline?
    assert_equal 'text', r.cache_key('text', side: :input)
  end

  def test_it_rewrites_rather_than_refusing
    result = check('Email me at someone@example.org with the answer.')
    assert result.modified?
    refute result.blocked?
    assert result.allowed?
  end
end
