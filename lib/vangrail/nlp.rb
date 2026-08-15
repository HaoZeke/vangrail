# frozen_string_literal: true

require 'set'

module Vangrail
  # Text analysis in the standard library: normalisation, a suffix stripper, a
  # concept lexicon with negation, and set similarity over character n-grams.
  #
  # A regexp matches the string an attacker wrote. Every published corpus shows
  # the same instruction arriving in a hundred wordings, and the wordings cost
  # an attacker one edit each while each new pattern costs a maintainer a
  # false-positive budget. What survives rewording is not the string; it is the
  # small set of concepts the sentence has to contain to do its job. An
  # injection has to name an override, or a secret, or an audience to hide
  # from, because a sentence that names none of them is not asking for
  # anything.
  #
  # So the text is reduced to concepts before anything judges it. That is a
  # lexicon, a stemmer, and a negation rule, which is decades-old NLP and runs
  # in microseconds with nothing loaded from disk. It is not an embedding and
  # cannot be: a synonym outside the lexicon is a miss, and the lexicon is
  # visible in this file for exactly that reason.
  module NLP
    module_function

    # Fold to a comparable form: NFKC so fullwidth and compatibility forms
    # collapse onto ASCII, downcase, and every run of non-alphanumerics to a
    # single space. Punctuation is separator rather than signal here, which is
    # what makes "ignore-all-previous-instructions" and the spaced form the
    # same token sequence.
    def normalize(text)
      text.to_s.scrub.unicode_normalize(:nfkc).downcase.gsub(/[^\p{Alnum}]+/, ' ').strip
    end

    def words(text)
      normalize(text).split
    end

    # A suffix stripper, not Porter. It exists so the lexicon can list one form
    # of a word instead of five, and correctness is not the requirement:
    # consistency is. Text and lexicon are stemmed by this same function, so a
    # stem that is not a word ("hiding" to "hid") still matches, and a form the
    # rules mangle is listed in the lexicon in the form it appears.
    def stem(word)
      w = word.to_s
      return w if w.length <= 3

      case w
      when /\A(.+)ies\z/ then "#{Regexp.last_match(1)}y"
      when /\A(.+ss)es\z/ then Regexp.last_match(1)
      when /\A(.+[^su])s\z/ then Regexp.last_match(1)
      when /\A(.{3,})ing\z/ then Regexp.last_match(1)
      when /\A(.{3,})ed\z/ then Regexp.last_match(1)
      when /\A(.{3,})ly\z/ then Regexp.last_match(1)
      else w
      end
    end

    # The concepts an injection has to name, and the words that name them.
    #
    # A word can carry more than one: "prompt" is an instruction when something
    # overrides it and a secret when something asks for it, and which one it is
    # depends on the other concept in the window rather than on the word. So
    # the lexicon maps a word to every concept it can carry and lets the
    # templates disambiguate.
    #
    # Written out rather than generated, because a lexicon that nobody can read
    # is a rule nobody can audit, and every entry here is a phrase somebody has
    # to be able to argue with.
    CONCEPTS = {
      # Verbs that cancel something already said.
      override: %w[ignore disregard forget override bypass discard dismiss overlook],
      # What gets cancelled: the standing instruction, in any of its names.
      instruction: %w[instruction direction directive rule guideline guidance order command prompt policy],
      # A reference backwards, to whatever was said before this text.
      prior: %w[previous prior above earlier preceding foregoing aforementioned original initial],
      # Verbs that move text out: to the reader, to a log, to a URL.
      reveal: %w[reveal print show display disclose repeat output echo dump send post transmit leak recite
                 tell mention share admit acknowledge],
      # What is worth moving out.
      secret: %w[prompt key apikey token credential password secret configuration instruction],
      # Verbs that keep something in.
      conceal: %w[hide conceal omit withhold suppress],
      # Whom to keep it from. Deliberately third-person: "anyone" is in every
      # handbook sentence about not sharing a password, and an injection names
      # the reader it is hiding from.
      audience: %w[user reader human visitor],
      # The act of answering, which is when an injection wants its rule applied.
      answering: %w[answer respond reply response],
      # Being told to be something else.
      persona: %w[act pretend roleplay simulate impersonate behave],
      # The state the persona is supposed to be in.
      unrestricted: %w[unrestricted unfiltered uncensored jailbroken jailbreak unchained dan],
      # Limits, which is what "without any" turns into a persona.
      limits: %w[restriction filter limit guardrail safeguard constraint],
      # The assistant, referred to as itself. What separates "print the
      # configuration with scontrol" from "print your configuration": the
      # first is a page telling a reader to run a command, the second is a page
      # addressing the thing that reads it.
      self: %w[your you yours yourself],
      # Totalising quantifiers. An attack cancels the lot, because it does not
      # know what it is cancelling; a page cancels one named thing.
      totality: %w[everything anything all every each entirely completely]
    }.freeze

    # Concepts that only exist as several words. A token lexicon cannot hold
    # "system prompt" without making "prompt" alone mean it, and "prompt" alone
    # is a word a shell handbook uses for the thing with the dollar sign in it.
    PHRASES = {
      'system prompt' => %i[secret],
      'developer message' => %i[secret],
      'initial instruction' => %i[secret],
      'api key' => %i[secret],
      'do anything now' => %i[unrestricted],
      'no longer bound' => %i[unrestricted]
    }.freeze

    # Words that flip the concept after them rather than adding one. "Never
    # mention this to the user" is concealment written with a revealing verb,
    # and "without restrictions" is an unrestricted persona written with a word
    # for limits. Handling that in the lexicon means the templates get the
    # concept the sentence means instead of the one it spells.
    NEGATORS = %w[not never dont doesnt cannot cant without no none neither nor avoid].freeze

    # What a negated concept becomes. A concept not listed here is dropped when
    # negated rather than transformed: "do not reveal the key" is concealment,
    # but "do not ignore the guidelines" is not an override, and treating it as
    # one flags the sentence that tells a reader to follow the rules.
    NEGATED = { reveal: :conceal, limits: :unrestricted }.freeze

    # How far a negator reaches. Three tokens covers "do not", "never", and
    # "do not ever", and stops short of the next clause.
    NEGATION_SCOPE = 3

    # stem => [concept, ...], built once. A plain hash rather than one with a
    # default block: this is frozen, and a default block that fills on lookup
    # would raise the first time an unknown word is read.
    lexicon = {}
    CONCEPTS.each do |concept, forms|
      forms.each { |form| (lexicon[stem(form)] ||= []) << concept }
    end
    lexicon.each_value(&:freeze)
    LEXICON = lexicon.freeze

    NEGATOR_STEMS = NEGATORS.map { |w| stem(w) }.to_set.freeze

    # Stemmed phrase => concepts, keyed by the joined stems so the lookup is
    # one hash hit per n-gram.
    stemmed_phrases = PHRASES.to_h { |phrase, found| [phrase.split.map { |w| stem(w) }.join(' '), found] }
    PHRASE_LEXICON = stemmed_phrases.freeze

    PHRASE_LENGTHS = PHRASE_LEXICON.keys.map { |k| k.count(' ') + 1 }.uniq.sort.reverse.freeze

    # "you" carries a persona only when something makes it a statement about
    # what the reader now is. A handbook says "you" in every second sentence
    # and means the person reading it, so the bare pronoun is worth nothing;
    # "you are now" is the sentence an injection needs and a page rarely
    # writes.
    COPULA = %w[are re be become becoming].map { |w| stem(w) }.to_set.freeze

    # Sentences, roughly, and clauses where the punctuation says so.
    #
    # Every rule over the concept stream is "these two concepts, close
    # together", and a rule that reaches across a full stop is reading two
    # statements as one. "Do not disclose your token to the desk; rotate it and
    # reply with the job id" is two instructions to a human, and only a window
    # that ignores the semicolon turns it into an instruction about answering.
    #
    # Splitting on more than the full stop is on purpose: the semicolon and the
    # colon separate statements too, and over-splitting only makes the rules
    # stricter, which is the safe direction for something that blocks.
    def clauses(text)
      text.to_s.scrub.split(/(?<=[.!?;:])\s+|\n+|\r+/).map(&:strip).reject(&:empty?)
    end

    # The text as [position, concept, surface word] triples.
    #
    # Positions are token indices rather than characters, because every rule
    # over this stream is "these two concepts, close together", and closeness
    # in words is what survives an attacker adding punctuation.
    def concepts(text)
      tokens = words(text)
      stems = tokens.map { |t| stem(t) }
      out = phrase_concepts(tokens, stems)
      stems.each_with_index do |s, i|
        out << [i, :persona, tokens[i]] if s == 'you' && COPULA.include?(stems[i + 1].to_s)
        found = LEXICON[s]
        next unless found

        negated = negated?(stems, i)
        found.each do |concept|
          if negated
            mapped = NEGATED[concept]
            next unless mapped

            concept = mapped
          end
          out << [i, concept, tokens[i]]
        end
      end
      out.sort_by! { |(i, concept, _)| [i, concept.to_s] }
      out
    end

    # Multiword concepts, reported at the position of their first token so the
    # window arithmetic treats a phrase as the one thing it is.
    def phrase_concepts(tokens, stems)
      out = []
      PHRASE_LENGTHS.each do |length|
        stems.each_cons(length).with_index do |window, i|
          found = PHRASE_LEXICON[window.join(' ')]
          next unless found

          found.each { |concept| out << [i, concept, tokens[i, length].join(' ')] }
        end
      end
      out
    end

    def negated?(stems, index)
      lower = [index - NEGATION_SCOPE, 0].max
      stems[lower...index].any? { |s| NEGATOR_STEMS.include?(s) }
    end

    # Character n-grams as a set. Character-level rather than word-level so a
    # typo, an inflection, or a joined word costs a few shingles instead of a
    # whole token.
    def shingles(text, size: 4)
      body = normalize(text)
      return Set[body] if body.length <= size

      (0..(body.length - size)).each_with_object(Set.new) { |i, acc| acc << body[i, size] }
    end

    # How much of `needle` appears in `haystack`, which is not how similar they
    # are. An injection is a sentence inside a page, so the overlap divided by
    # the union is small however exact the match: the page dominates the union.
    # Containment asks the question the case actually poses, "is this thing in
    # there", and is the standard measure for it.
    def containment(needle, haystack)
      return 0.0 if needle.empty?

      (needle & haystack).size.fdiv(needle.size)
    end

    def jaccard(left, right)
      union = (left | right).size
      return 0.0 if union.zero?

      (left & right).size.fdiv(union)
    end
  end
end
