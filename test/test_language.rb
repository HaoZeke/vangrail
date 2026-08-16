# frozen_string_literal: true

require_relative 'helper'

# The guarantee, extended to languages: nothing reports a clean check it did not
# perform, and a page in German is a page none of the deterministic rails can
# read.
class TestLanguage < Minitest::Test
  GERMAN = TestCorpus::GERMAN
  FRENCH = TestCorpus::FRENCH

  def rail
    @rail ||= Vangrail::Rails::Language.new
  end

  def check(text)
    rail.call(text, side: :context)
  end

  def test_a_page_in_english_is_read_and_says_so
    result = check(TestCorpus::ENGLISH_BENIGN.join(' '))

    assert_predicate result, :passed?
    assert_predicate result, :certain?
  end

  def test_a_page_in_dutch_is_read_and_says_so
    result = check(TestCorpus::DUTCH_BENIGN.join(' '))

    assert_predicate result, :passed?
    assert_predicate result, :certain?
  end

  # The point of the rail. Not blocked, because an unsupported language is not
  # an attack; not certain either, because nothing read it.
  def test_a_page_in_an_unsupported_language_is_passed_and_uncertain
    [GERMAN, FRENCH].each do |page|
      result = check(page)

      assert_predicate result, :passed?
      refute_predicate result, :certain?
      assert_match(/not in a language this engine reads/, result.reason)
    end
  end

  # A short text is not evidence of a language, in either direction. Reporting
  # uncertainty on every six-word question would make the posture noise.
  def test_a_short_text_is_left_alone
    result = check('How do I submit a GPU job?')

    assert_predicate result, :passed?
    assert_predicate result, :certain?
  end

  # Twelve tokens is the detector's floor, and a handbook sentence that
  # sits there often has too few function words to be named. That is not
  # a page in German.
  def test_a_short_handbook_sentence_is_not_called_foreign
    result = check('Your home quota is 200 GB; project space is allocated per grant.')

    assert_predicate result, :passed?
    assert_predicate result, :certain?
  end

  def test_the_supported_set_is_what_decides
    dutch_only = Vangrail::Rails::Language.new(supported: [:nl])
    english = TestCorpus::ENGLISH_BENIGN.join(' ')

    refute_predicate dutch_only.call(english, side: :context), :certain?
    assert_predicate rail.call(english, side: :context), :certain?
  end

  # An engine's whole answer has to carry it, or the rail is a fact nobody
  # reads. Input as well as context: a long German question used to
  # certain-pass `check_input` because the posture rail only sat on
  # retrieved pages.
  def test_the_uncertainty_reaches_the_engine
    engine = Vangrail::Engine.new(context: [rail, Vangrail::Rails::InjectedInstructions.new],
                                  input: [rail, Vangrail::Rails::Paraphrase.new(sides: [:input])])
    result = engine.check_context(GERMAN)

    assert_predicate result, :passed?
    refute_predicate result, :certain?

    asked = engine.check_input(GERMAN)

    assert_predicate asked, :passed?
    refute_predicate asked, :certain?
  end

  def test_it_is_offline_and_memoizable
    assert_predicate rail, :offline?
    assert_predicate rail, :posture?
    refute_predicate rail, :language_agnostic?
    assert_equal "en+nl\ntext", rail.cache_key('text', {})
  end

  # A German clause inside an English page is unread. Function-word
  # counts over the whole string call it English and used to certain-pass.
  def test_a_foreign_clause_in_an_english_page_is_unread
    page = "#{TestCorpus::ENGLISH_BENIGN.first}\n\n#{GERMAN}\n\nSee the reference pages."
    result = check(page)

    assert_predicate result, :passed?
    refute_predicate result, :certain?
  end

  def test_markup_budget_and_canary_do_not_care_what_language_the_words_are_in
    [Vangrail::Rails::Markup.new, Vangrail::Rails::Budget.new,
     Vangrail::Rails::Canary.new(tokens: ['marker']), Vangrail::Rails::Secrets.new].each do |r|
      assert_predicate r, :language_agnostic?, r.name
    end
  end

  # The detector on its own, since every rule above rests on it.
  def test_the_detector_calls_the_two_languages_it_knows
    assert_equal :en, Vangrail::NLP.language(TestCorpus::ENGLISH_BENIGN.join(' '))
    assert_equal :nl, Vangrail::NLP.language(TestCorpus::DUTCH_BENIGN.join(' '))
    assert_equal :unknown, Vangrail::NLP.language(GERMAN)
    assert_equal :unknown, Vangrail::NLP.language(FRENCH)
  end
end
