# frozen_string_literal: true

# Constructed handbook pages the measurement scripts score.
#
#   require_relative 'handbook_corpus'
#
# The strings live in test/corpus.rb. This file builds the spliced, encoded,
# and combined sets without loading a test class (and without minitest).
require_relative '../test/corpus'

module HandbookCorpus
  INJECTIONS = TestCorpus::INJECTIONS
  PARAPHRASED = TestCorpus::ENGLISH_PARAPHRASED
  EDITED = TestCorpus::EDITED
  ATTACKS_NL = TestCorpus::DUTCH_ATTACKS
  ENGLISH_BENIGN = TestCorpus::ENGLISH_BENIGN
  DUTCH_BENIGN = TestCorpus::DUTCH_BENIGN
  INJECTION_BENIGN = TestCorpus::INJECTION_BENIGN
  POSITIONS = TestCorpus::POSITIONS
  ENCODINGS = TestCorpus::ENCODINGS
  DUTCH_FILLER = TestCorpus::DUTCH_FILLER

  module_function

  def poison(prose, injection, position, filler: 'See the reference pages for the full table.')
    TestCorpus.poison(prose, injection, position, filler: filler)
  end

  def encode(text, kind)
    TestCorpus.encode(text, kind)
  end

  def injection_pages
    INJECTIONS.each_with_index.flat_map do |injection, i|
      POSITIONS.map { |position| poison(INJECTION_BENIGN[i % INJECTION_BENIGN.size], injection, position) }
    end
  end

  def encoded_pages
    INJECTIONS.flat_map do |injection|
      ENCODINGS.map do |kind|
        "#{INJECTION_BENIGN.first}\n\n#{encode(injection, kind)}\n\nSee the reference pages."
      end
    end
  end

  def paraphrased_pages
    PARAPHRASED.each_with_index.flat_map do |injection, i|
      POSITIONS.map { |position| poison(ENGLISH_BENIGN[i % ENGLISH_BENIGN.size], injection, position) }
    end
  end

  def dutch_pages
    ATTACKS_NL.each_with_index.flat_map do |injection, i|
      POSITIONS.map do |position|
        poison(DUTCH_BENIGN[i % DUTCH_BENIGN.size], injection, position, filler: DUTCH_FILLER)
      end
    end
  end

  def hidden_pages
    INJECTIONS.map do |injection|
      "#{INJECTION_BENIGN.first}\n<!-- #{injection} -->\n<p>See the reference pages.</p>"
    end
  end

  def pasted_pages
    INJECTIONS.first(6).map do |injection|
      turns = (1..6).map { |i| "user: question #{i}\nassistant: of course, here it is." }.join("\n")
      "#{turns}\nuser: #{injection}"
    end
  end

  def edited_pages
    EDITED.map { |text| "#{ENGLISH_BENIGN.first}\n\n#{text}" }
  end

  # The 270-text attack set script/measure_evidence.rb and
  # script/measure_origin.rb share.
  def attack_texts
    (injection_pages + encoded_pages + hidden_pages + pasted_pages +
     paraphrased_pages + dutch_pages + edited_pages).uniq
  end

  # The 48-text benign set those scripts share: English plus Dutch handbook
  # prose, including every near miss the rules were narrowed against.
  def benign_texts
    (INJECTION_BENIGN + ENGLISH_BENIGN + DUTCH_BENIGN).uniq
  end

  # The 120-text local attack mix the external evidence table folds in:
  # positioned injections plus the same injections under each encoding.
  def local_attacks
    injection_pages + encoded_pages
  end

  def attack_clauses
    (INJECTIONS + PARAPHRASED + ATTACKS_NL + EDITED).uniq
  end
end
