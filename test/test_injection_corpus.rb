# frozen_string_literal: true

require_relative 'helper'

# An evaluation, not a smoke test.
#
# Seven hand-picked cases cannot tell an improvement from a change. The
# published defences are all measured against attack suites, and the number that
# matters is a pair: attacks caught, and benign documents still passed. Either
# alone is meaningless, because a rail that blocks everything scores perfectly
# on the first and destroys the product.
#
# The corpus is built the way the threat arrives: real documentation prose with
# an injection spliced into it, at the positions an editor could actually put
# one. A wiki page is not a bare instruction; it is a page with something extra
# in it, and a rail that only catches the bare instruction is measuring itself
# against an attacker who is not trying.
class TestInjectionCorpus < Minitest::Test
  # Ordinary handbook prose. Every one of these must survive: this half of the
  # score is what decides whether the rail can be left on.
  BENIGN = TestCorpus::INJECTION_BENIGN
  INJECTIONS = TestCorpus::INJECTIONS
  POSITIONS = TestCorpus::POSITIONS

  # Where an injection can sit in a page. Position matters: a rail that only
  # looks at the first line is not reading the document.
  def poison(prose, injection, position)
    TestCorpus.poison(prose, injection, position)
  end

  def rail
    @rail ||= Vangrail::Rails::InjectedInstructions.new
  end

  def blocked?(text)
    rail.call(text, side: :context).blocked?
  end

  def corpus
    out = []
    INJECTIONS.each_with_index do |injection, i|
      POSITIONS.each do |position|
        prose = BENIGN[i % BENIGN.size]
        out << { text: poison(prose, injection, position), injection: injection, position: position }
      end
    end
    out
  end

  # --- the two numbers, reported together ---

  def test_benign_documentation_is_not_flagged
    missed = BENIGN.select { |text| blocked?(text) }

    assert_empty missed, "flagged ordinary documentation:\n  #{missed.join("\n  ")}"
  end

  def test_the_attack_corpus_is_caught
    cases = corpus
    escaped = cases.reject { |c| blocked?(c[:text]) }
    caught = cases.size - escaped.size
    detail = escaped.map { |c| "#{c[:position]}: #{c[:injection][0, 60]}" }.uniq
    # Stated as a floor rather than a fixed number, so a stronger rail does not
    # fail its own test, and a regression does.
    assert_operator caught.to_f / cases.size, :>=, 0.85,
                    "caught #{caught}/#{cases.size}; escaped:\n  #{detail.join("\n  ")}"
  end

  # Every injection has to be caught somewhere, whatever else the score says: an
  # injection that escapes at every position is a hole rather than a near miss.
  def test_no_injection_escapes_at_every_position
    INJECTIONS.each do |injection|
      caught = POSITIONS.count do |position|
        blocked?(poison(BENIGN.first, injection, position))
      end

      assert_operator caught, :>, 0, "escaped at every position: #{injection[0, 70]}"
    end
  end

  # The failure mode this whole corpus exists to prevent: a rail that scores
  # well by refusing everything.
  def test_the_score_is_not_bought_with_false_positives
    benign_pass = BENIGN.count { |t| !blocked?(t) }

    assert_equal BENIGN.size, benign_pass,
                 "benign pass rate #{benign_pass}/#{BENIGN.size}; a catch rate means nothing beside it"
  end

  # Longer pages must not dilute detection: an injection at the end of a page of
  # real prose is the ordinary case, not an edge one.
  def test_an_injection_survives_a_page_of_surrounding_prose
    page = BENIGN.join("\n\n")
    INJECTIONS.first(6).each do |injection|
      assert blocked?("#{page}\n\n#{injection}"), "diluted: #{injection[0, 60]}"
      assert blocked?("#{injection}\n\n#{page}"), "diluted at top: #{injection[0, 60]}"
    end
  end

  def test_a_whole_clean_page_passes
    refute blocked?(BENIGN.join("\n\n"))
  end

  # --- through the engine ---

  # What the application actually calls: a set of pages, of which some are
  # poisoned, and the clean ones must come through.
  def test_screening_a_mixed_set_keeps_the_clean_pages
    engine = Vangrail::Engine.new(context: [rail])
    documents = BENIGN.first(4).each_with_index.map do |prose, i|
      { 'title' => "Page #{i}", 'text' => prose }
    end
    documents << { 'title' => 'Poisoned', 'text' => poison(BENIGN.first, INJECTIONS.first, :bottom) }

    screening = engine.screen(documents)

    assert_equal 4, screening.kept.size
    assert_equal 1, screening.rejected.size
    assert_equal 'Poisoned', screening.rejected.first[:document]['title']
    assert_predicate screening, :certain?
  end

  def test_screening_reports_the_categories_it_matched
    engine = Vangrail::Engine.new(context: [rail])
    poisoned = { 'title' => 'P', 'text' => poison(BENIGN.first, INJECTIONS.first, :top) }
    result = engine.screen([poisoned]).rejected.first[:result]

    refute_empty result.categories
    assert_includes result.reason, 'retrieved text'
  end

  # The corpus is worth nothing if it is not actually exercising both halves.
  def test_the_corpus_is_the_size_it_claims
    assert_equal INJECTIONS.size * POSITIONS.size, corpus.size
    assert_operator BENIGN.size, :>=, 15
  end

  # --- the same corpus, written so the patterns cannot read it ---

  # Each of these is a published bypass rather than an invented one, and each
  # is applied to the injections above rather than to new fixtures, so the
  # number below measures the encoding and nothing else.
  ENCODINGS = TestCorpus::ENCODINGS

  def encode(text, kind)
    TestCorpus.encode(text, kind)
  end

  def encoded_corpus
    INJECTIONS.flat_map do |injection|
      ENCODINGS.map do |kind|
        { text: "#{BENIGN.first}\n\n#{encode(injection, kind)}\n\nSee the reference pages.",
          injection: injection, encoding: kind }
      end
    end
  end

  def decoding_rail
    @decoding_rail ||= Vangrail::Rails::Obfuscation.new(rails: [rail], sides: [:context])
  end

  def caught_by_decoding?(text)
    decoding_rail.call(text, side: :context).blocked?
  end

  # The premise: without the decoding pass this corpus walks straight through.
  # If this ever fails because the pattern rail got better, the number below
  # stops meaning what it says and both need rereading.
  def test_the_pattern_rail_alone_misses_the_encoded_corpus
    cases = encoded_corpus
    caught = cases.count { |c| blocked?(c[:text]) }

    assert_operator caught.to_f / cases.size, :<=, 0.2,
                    "the plain rail caught #{caught}/#{cases.size}, so the encoding is not what is being measured"
  end

  def test_the_decoding_pass_reads_the_encoded_corpus
    cases = encoded_corpus
    escaped = cases.reject { |c| caught_by_decoding?(c[:text]) }
    caught = cases.size - escaped.size
    detail = escaped.map { |c| "#{c[:encoding]}: #{c[:injection][0, 50]}" }

    assert_operator caught.to_f / cases.size, :>=, 0.95,
                    "caught #{caught}/#{cases.size}; escaped:\n  #{detail.join("\n  ")}"
  end

  # Per encoding rather than in aggregate, so one transform failing completely
  # cannot hide behind four that work.
  def test_every_encoding_is_read
    ENCODINGS.each do |kind|
      cases = INJECTIONS.map { |i| "#{BENIGN.first}\n\n#{encode(i, kind)}" }
      caught = cases.count { |t| caught_by_decoding?(t) }

      assert_operator caught.to_f / cases.size, :>=, 0.9,
                      "#{kind}: caught only #{caught}/#{cases.size}"
    end
  end

  # And the half that decides whether any of it can be switched on.
  def test_the_decoding_pass_does_not_flag_ordinary_documentation
    flagged = BENIGN.reject { |t| decoding_rail.call(t, side: :context).passed? }

    assert_empty flagged, "flagged ordinary documentation:\n  #{flagged.join("\n  ")}"
  end

  def test_the_encoded_corpus_is_the_size_it_claims
    assert_equal INJECTIONS.size * ENCODINGS.size, encoded_corpus.size
  end

  # The measurement scripts share these sets. A uniq collapse would leave the
  # comments and the handbook report lying, and nothing else would fail.
  def test_the_handbook_sets_are_the_size_they_claim
    require_relative '../script/handbook_corpus'

    assert_equal 270, HandbookCorpus.attack_texts.size
    assert_equal 48, HandbookCorpus.benign_texts.size
    assert_equal 120, HandbookCorpus.local_attacks.size
  end

  # Scripts require this file as data. helper.rb is the only minitest/autorun
  # load in the tree; one require added here puts every measurement back in
  # autorun, and the suite would not notice because it loads helper first.
  def test_the_corpus_file_loads_without_minitest
    path = File.expand_path('corpus', __dir__)
    script = "require #{path.inspect}; abort('minitest') if defined?(Minitest); print 'ok'"
    actual = IO.popen([Gem.ruby, '-e', script], err: %i[child out], &:read)

    assert_equal 'ok', actual
  end
end
