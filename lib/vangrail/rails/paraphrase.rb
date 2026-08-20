# frozen_string_literal: true

require_relative '../nlp'
require_relative '../rail'

module Vangrail
  module Rails
    # Catches the injection that was reworded.
    #
    # Rails::InjectedInstructions and Rails::Jailbreak match strings, and a
    # string is what an attacker edits first. "Ignore all previous
    # instructions" is one thesaurus away from "discard every guideline stated
    # so far", which no pattern in this gem matches and which asks for exactly
    # the same thing. That gap is stated plainly in the coverage page, and this
    # rail is the part of it that can be closed without a model.
    #
    # The move is to stop matching words. The text is reduced to concepts
    # first (NLP.concepts), and what gets matched is a pair of concepts close
    # together: an override next to an instruction, a revealing verb next to a
    # secret, concealment next to an audience, a persona next to a state with
    # no rules in it. A rewording that keeps the meaning keeps the concepts,
    # because the concepts are what the sentence is for.
    #
    # Two concepts rather than one, always. A document that mentions
    # instructions is a handbook; a document that mentions overriding them is
    # an attack. Every single-concept rule tried against the corpus flagged
    # ordinary documentation, and the pair is what separates the two without a
    # judgement call.
    #
    # Because concepts are language-independent, a second language costs a word
    # list rather than a second rail. English and Dutch are both read by
    # default: the pattern rails in this gem are English-only, so a Dutch wiki
    # page is a page nothing else here can read, and at a Dutch institution
    # that page is the ordinary case rather than the exotic one.
    #
    # The limits are worth being exact about, because this is the rail most
    # likely to be mistaken for understanding. A synonym outside NLP::CONCEPTS
    # is a miss. A sentence in another language is a miss. An attacker who
    # reads this file can pick words that are in no list here, exactly as they
    # can with the patterns. What it buys is that rewording no longer costs an
    # attacker one edit, and that the cheap rewrites that beat a regexp do not
    # beat this.
    class Paraphrase < Rail
      # Each entry is two concepts and how far apart they may sit, in tokens.
      # The windows are short because closeness is the whole claim: two
      # concepts in one clause are one statement, and the same two concepts
      # nine lines apart are two unrelated sentences in a long page.
      # Cancel the standing instruction, however it is named. Ordered, because
      # an override governs its object: "ignore the guidelines" is an attack
      # and "follow the guidance and ignore stale copies of it" has the same
      # two concepts in the other order and is a handbook sentence.
      TEMPLATES = [
        { label: 'instruction_override', concepts: %i[override instruction], window: 6, ordered: true },
        # Cancel what came before without naming it. "Ignore the earlier
        # warning" is a page; "dismiss anything stated earlier" is an attack,
        # and the quantifier is the difference. An attacker cancels the lot
        # because they do not know what they are cancelling.
        { label: 'instruction_override', concepts: %i[override prior], window: 4, ordered: true,
          requires: %i[totality] },
        # Move a secret out. The clause has to address the assistant: "print
        # the configuration with scontrol" tells a reader to run a command,
        # "print your configuration" talks to the thing reading the page.
        { label: 'prompt_disclosure', concepts: %i[reveal secret], window: 8, ordered: true,
          requires: %i[self] },
        # Keep something from the person reading the answer. Both halves are
        # needed: concealment alone is security advice ("never mention a
        # password in a ticket"), and an audience alone is every support page.
        { label: 'answer_shaping', concepts: %i[conceal audience], window: 10 },
        { label: 'answer_shaping', concepts: %i[conceal answering], window: 10 },
        # Be something without rules.
        { label: 'unrestricted_persona', concepts: %i[persona unrestricted], window: 8 },
      ].freeze

      attr_reader :templates, :languages

      # Both languages by default. A deployment whose corpus is genuinely
      # single-language can say so and pay a shorter lexicon; one that thinks
      # it is single-language usually has a Dutch page in it somewhere, which
      # is the case the default is for.
      def initialize(templates: TEMPLATES, languages: NLP::LANGUAGES, name: 'paraphrase',
                     sides: %i[input context])
        super(name: name, sides: sides)
        @templates = templates
        @languages = Array(languages).map(&:to_sym)
        unknown = @languages - NLP::LANGUAGES
        raise ArgumentError, "unknown language(s): #{unknown.join(', ')}" unless unknown.empty?
      end

      def cache_key(text, _context)
        "#{languages.join('+')}\n#{text}"
      end

      def decide(text, _context)
        # Clause by clause: a rule that reaches across a full stop is reading
        # two statements as one, and a long page has a full stop every line.
        # Anaphora is applied across that cut: "Ignore them" after a clause
        # that named an instruction is the same pair as "Ignore the instructions".
        clauses = NLP.clauses(text)
        hits = NLP.clause_concepts(text, languages: languages).flat_map.with_index do |found, i|
          clause_hits(clauses[i], found)
        end
        return pass if hits.empty?

        block(categories: hits.map { |hit| hit[:label] }.uniq,
              reason: "reworded instruction: #{hits.map { |hit| describe(hit) }.uniq.join('; ')}")
      end

      private

      def clause_hits(clause, found = nil)
        found ||= NLP.concepts(clause, languages: languages)
        return [] if found.empty?

        present = found.to_set { |(_, concept, _)| concept }
        length = NLP.words(clause).size
        templates.filter_map do |template|
          next unless Array(template[:requires]).all? { |concept| present.include?(concept) }

          match(found, template, length)
        end
      end

      # Pairs within a window, found by walking the window rather than by
      # comparing everything with everything.
      #
      # The obvious loop is lefts against rights, and it is quadratic in the
      # number of concepts a document carries. That is invisible on ordinary
      # prose, where a clause holds two or three, and it is reachable on
      # purpose: a retrieved page is written by whoever wants it retrieved, and
      # a page of "ignore ignore ignore ... instructions instructions" carries
      # thousands of each with no pair close enough to match, so every one gets
      # compared against every one. Measured before this rewrite: 51 ms at 5 KB,
      # 1,298 ms at 39 KB, four times the work for twice the page, and the
      # decoding pass runs it again per transform.
      #
      # A window is at most ten tokens, so walking it costs the same per concept
      # whatever the page weighs.
      def match(found, template, length)
        first, second = template[:concepts]
        seconds = Hash.new { |hash, key| hash[key] = [] }
        found.each { |(index, concept, word)| seconds[index] << word if concept == second }
        window = template[:window]

        found.each do |(i, concept, left_word)|
          next unless concept == first

          ((i - window)..(i + window)).each do |j|
            # One word carrying both concepts is one fact, not two. "prompt" is
            # an instruction and a secret at the same index, and a page that
            # says it once has not said anything twice.
            next if j == i
            next if template[:ordered] && j < i && !verb_final_object?(i, length, left_word)

            right_word = seconds[j].first
            next unless right_word

            return { label: template[:label], words: [left_word, right_word] }
          end
        end
        nil
      end

      # Dutch subordinates put the verb last, so the object of an override
      # sits to its left: "dat je de richtlijnen negeert". English "follow
      # the guidance and ignore stale copies" has the override mid-clause
      # with its own object after it, and stays unflagged.
      #
      # The verb has to be a Dutch one, because the rule is Dutch grammar and
      # English ends clauses with these verbs constantly. Measured over 699
      # installed manual pages, the position test alone took this rail from
      # 1.6% of documents to 5.2%, and every added flag was a documentation URL
      # whose last token happened to be "overrides":
      #
      #   <https://doc.rust-lang.org/cargo/reference/config.html#command-line-overrides>
      #
      # The two override lexicons are disjoint, so asking which language the
      # verb came from costs one lookup and gives the rule back its subject.
      DUTCH_OVERRIDES = NLP::CONCEPTS[:nl][:override].to_set { |word| NLP.stem(word) }.freeze

      def verb_final_object?(verb_index, length, word)
        verb_index == length - 1 && DUTCH_OVERRIDES.include?(NLP.stem(NLP.normalize(word)))
      end

      def describe(hit)
        "#{hit[:label]} (#{hit[:words].join(' ... ')})"
      end
    end
  end
end
