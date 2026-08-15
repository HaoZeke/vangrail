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
        { label: 'unrestricted_persona', concepts: %i[persona unrestricted], window: 8 }
      ].freeze

      attr_reader :templates

      def initialize(templates: TEMPLATES, name: 'paraphrase', sides: %i[input context])
        super(name: name, sides: sides)
        @templates = templates
      end

      def offline?
        true
      end

      def cache_key(text, _context)
        text
      end

      def call(text, _context)
        # Clause by clause: a rule that reaches across a full stop is reading
        # two statements as one, and a long page has a full stop every line.
        hits = NLP.clauses(text).flat_map { |clause| clause_hits(clause) }
        return pass if hits.empty?

        block(categories: hits.map { |hit| hit[:label] }.uniq,
              reason: "reworded instruction: #{hits.map { |hit| describe(hit) }.uniq.join('; ')}")
      end

      private

      def clause_hits(clause)
        found = NLP.concepts(clause)
        return [] if found.empty?

        present = found.map { |(_, concept, _)| concept }.to_set
        templates.filter_map do |template|
          next unless Array(template[:requires]).all? { |concept| present.include?(concept) }

          match(found, template)
        end
      end

      def match(found, template)
        first, second = template[:concepts]
        lefts = found.select { |(_, concept, _)| concept == first }
        rights = found.select { |(_, concept, _)| concept == second }

        lefts.each do |(i, _, left_word)|
          rights.each do |(j, _, right_word)|
            # One word carrying both concepts is one fact, not two. "prompt" is
            # an instruction and a secret at the same index, and a page that
            # says it once has not said anything twice.
            next if i == j
            next if template[:ordered] && j < i
            next if (i - j).abs > template[:window]

            return { label: template[:label], words: [left_word, right_word] }
          end
        end
        nil
      end

      def describe(hit)
        "#{hit[:label]} (#{hit[:words].join(' ... ')})"
      end
    end
  end
end
