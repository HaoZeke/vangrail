# frozen_string_literal: true

require_relative '../known_attacks'
require_relative '../nlp'
require_relative '../rail'

module Vangrail
  module Rails
    # Catches the known attack that was edited rather than reworded.
    #
    # A published jailbreak spreads by being pasted, and what arrives is a near
    # copy: a typo, two words inserted, different capitals, a word inflected
    # differently, an exclamation mark added. A regexp misses all of those
    # unless somebody widens it for each one, and every widening is spent from
    # the same false-positive budget. Near-duplicate detection is the standard
    # answer, and the standard measure is containment over character n-grams:
    # how much of the known sentence is present in the text, rather than how
    # similar the two are overall.
    #
    # Containment rather than Jaccard, because the case is a sentence inside a
    # page. A wiki page with one pasted jailbreak in it is 99% ordinary prose,
    # so overlap over union is near zero however exact the copy, and the
    # measure that answers "is this in there" is the one that divides by the
    # seed.
    #
    # Clause by clause rather than page by page, and that is not a detail. A
    # long page accidentally contains most of the four-character n-grams of any
    # short English sentence: measured against the benign corpus in this repo,
    # a page of ordinary documentation scores 0.94 against a seed it does not
    # contain, and the same corpus split into clauses scores 0.67. Containment
    # saturates with length, so the comparison has to be against a span the
    # size of the thing being looked for.
    #
    # What this does not do is judge. A clause either reproduces a sentence
    # somebody published or it does not; there is no scoring of intent, and a
    # novel attack in nobody's corpus scores zero here by construction.
    class Similarity < Rail
      # Measured on the corpora in this repo: ordinary documentation tops out
      # at 0.67 against the nearest seed, and edited copies of the seeds bottom
      # out at 0.83. The gap is where the threshold goes, and 0.75 is the
      # middle of it rather than a round number picked first.
      THRESHOLD = 0.75

      # Four characters: long enough that a shingle is a fragment of a word
      # rather than a letter pair, short enough that a typo costs four shingles
      # instead of a whole token.
      SHINGLE = 4

      attr_reader :threshold, :seeds

      def initialize(seeds: KnownAttacks::ALL, threshold: THRESHOLD, shingle: SHINGLE,
                     name: 'similarity', sides: %i[input context])
        super(name: name, sides: sides)
        @threshold = threshold
        @shingle = shingle
        @seeds = seeds.map { |seed| [seed, NLP.shingles(seed, size: shingle)] }.freeze
        # Every n-gram any seed contains, and the smallest number of them a
        # clause needs before any seed can possibly clear the threshold. One
        # intersection against this decides whether the clause is worth
        # comparing seed by seed, and on ordinary prose it decides no. The
        # bound is exact rather than heuristic: a clause sharing fewer grams
        # with the union than the shortest seed needs cannot contain any seed.
        @union = @seeds.flat_map { |(_, shingles)| shingles.to_a }.to_set.freeze
        @floor = (threshold * @seeds.map { |(_, shingles)| shingles.size }.min).ceil
      end

      def offline?
        true
      end

      def cache_key(text, _context)
        "#{threshold}\n#{text}"
      end

      def call(text, _context)
        score, seed = nearest(text)
        return pass if score < threshold

        block(categories: ['known_attack'],
              reason: format('near copy of a known attack (%<score>.2f): %<seed>s', score: score, seed: seed))
      end

      # The closest seed and how much of it is present, for a caller that wants
      # the number rather than the verdict.
      def nearest(text)
        best = [0.0, nil]
        NLP.clauses(text).each do |clause|
          present = NLP.shingles(clause, size: @shingle)
          next if (present & @union).size < @floor

          seeds.each do |(seed, shingles)|
            score = NLP.containment(shingles, present)
            best = [score, seed] if score > best.first
          end
        end
        best
      end
    end
  end
end
