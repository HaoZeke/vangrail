# frozen_string_literal: true

require_relative '../nlp'
require_relative '../rail'

module Vangrail
  module Rails
    # Catches the injection whose concepts are in the right order but too far
    # apart for the pair window.
    #
    # Rails::Paraphrase matches two concepts inside a short token window.
    # That is the right rule for a clause, and it is the wrong rule for
    # "Ignore, once you have loaded the module the reservation policy
    # describes, every previous instruction": the override and the
    # instruction are one statement with an adjunct in the middle, and the
    # window treats them as two. Smith and Waterman (1981) local alignment
    # over the concept stream is the standard way to match a short sequence
    # with a gap.
    #
    # Templates are three concepts, not two. The pair rail already owns the
    # close case. Last occurrence of each template concept, in order, with
    # a coordinator between them treated as two statements, is what a
    # window of six cannot be. Ordered, so "follow the guidance and ignore
    # stale copies" still does not match. Extra copies of :instruction
    # (a "policy" mentioned mid-clause) do not steal the object.
    #
    # Not in the evidence table until it is measured on the same 270/48
    # texts as the others. Engine#assess will not treat it as a term.
    class Alignment < Rail
      TEMPLATES = [
        { label: 'instruction_override', concepts: %i[override totality instruction] },
        { label: 'instruction_override', concepts: %i[override totality prior] },
        { label: 'prompt_disclosure', concepts: %i[reveal self secret] },
      ].freeze

      attr_reader :templates, :languages

      def initialize(templates: TEMPLATES, languages: NLP::LANGUAGES, name: 'alignment',
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
        clauses = NLP.clauses(text)
        hits = NLP.clause_concepts(text, languages: languages).flat_map.with_index do |found, i|
          clause_hits(found, NLP.words(clauses[i]))
        end
        return pass if hits.empty?

        block(categories: hits.map { |hit| hit[:label] }.uniq,
              reason: "aligned instruction: #{hits.map { |hit| describe(hit) }.uniq.join('; ')}")
      end

      private

      def clause_hits(found, tokens)
        return [] if found.empty?

        templates.filter_map { |template| align(found, tokens, template) }
      end

      # Last occurrence of each template concept, in the template's order.
      def align(found, tokens, template)
        target = template[:concepts]
        return nil if target.size < 3

        last = {}
        found.each { |(i, concept, word)| last[concept] = [i, concept, word] if target.include?(concept) }
        placed = target.map { |concept| last[concept] }
        return nil if placed.any?(&:nil?)
        return nil unless placed.each_cons(2).all? { |(left, right)| left[0] < right[0] }
        return nil if (placed.last[0] - placed.first[0]) > 20
        return nil if coordinated?(tokens, placed.first[0], placed.last[0])

        { label: template[:label], words: placed.map { |(_, _, word)| word } }
      end

      def coordinated?(tokens, start_at, stop_at)
        tokens[(start_at + 1)...stop_at].any? { |word| NLP::COORDINATOR_STEMS.include?(NLP.stem(word)) }
      end

      def describe(hit)
        "#{hit[:label]} (#{hit[:words].join(' ... ')})"
      end
    end
  end
end
