# frozen_string_literal: true

require_relative '../bayes_data'
require_relative '../nlp'
require_relative '../rail'

module Vangrail
  module Rails
    # A naive Bayes classifier over word n-grams, which is the oldest working
    # text classifier there is and the only rail here that says how sure it is.
    #
    # Every other rail answers yes or no, so it hands the evidence arithmetic
    # exactly one bit of information however certain it was. This one computes a
    # log-likelihood ratio directly, which is the quantity that arithmetic
    # actually wants: a clause scoring twelve bits and a clause scoring three
    # both "fire", and they are not the same observation. A rail that puts
    # `bits` in its result's `raw` is read that way by Engine#assess, and this is
    # the first rail to do it.
    #
    # Scored clause by clause, taking the worst. The same dilution problem the
    # containment rail hit applies here with force: an attack document is
    # ordinary documentation with one injected sentence in it, and a bag of
    # features over the whole page is mostly evidence about the handbook.
    #
    # The shipped weights are a demonstration, and the honest number says so.
    # Source groups have disjoint train, calibration, threshold, and final-test
    # roles. On six final-test attacks and six benign pages, the selected
    # threshold catches three attacks and flags two benign pages. Six calibration
    # attacks defend no positive likelihood-ratio bits at 95% joint credibility.
    # The junk-mail filters this borrows from were fitted on millions of examples.
    #
    # So it is off by default, and what it is for is the retraining path: a
    # deployment with its own traffic runs script/train_bayes.rb against its own
    # corpus and gets a rail fitted to the attacks it actually receives, with
    # separate calibration, threshold, and final-test evidence.
    class Bayes < Rail
      def initialize(weights: BayesData::WEIGHTS, threshold: BayesData::THRESHOLD,
                     calibration: BayesData::CALIBRATION, name: 'bayes', sides: %i[input context])
        super(name: name, sides: sides)
        @weights = weights
        @threshold = threshold
        @calibration = calibration
      end

      attr_reader :weights, :threshold, :calibration

      def quantifies?
        true
      end

      def cache_key(text, _context)
        "#{threshold}\n#{text}"
      end

      def decide(text, _context)
        score = score_for(text)
        evidence = bits_for(score)
        payload = { 'bits' => evidence, 'score' => score }
        # A positive score at or below the threshold is not a decision. The
        # threshold role did not select it, and the small calibration role cannot
        # defend positive evidence for it.
        if uncertain_score?(score)
          return unchecked('score sits in a band the calibration cannot separate', raw: payload)
        end
        return pass(raw: payload) if score <= threshold

        block(categories: ['bayes'], raw: payload,
              reason: format('scores %<score>+.1f, worth %<bits>+.1f bits of evidence', score: score,
                                                                                        bits: evidence))
      end

      def uncertain_score?(score)
        score.positive? && score <= threshold
      end

      # The worst clause's raw naive Bayes score. Not a likelihood ratio and not
      # to be added to one: the features are counted as independent and are not,
      # so this number is confidently wrong about its own size. It decides the
      # block, because a threshold only needs an ordering.
      def score_for(text)
        clauses = NLP.clauses(text)
        return clause_score(text.to_s) if clauses.empty?

        clauses.map { |clause| clause_score(clause) }.max
      end

      # What that score is worth, fitted only on the calibration role and read at
      # the simultaneous 95% likelihood-ratio bound. This is the number that goes
      # into a posterior; unsupported score bands contribute zero.
      def bits(text)
        bits_for(score_for(text))
      end

      def bits_for(score)
        band = calibration.reverse.detect { |floor, _| score > floor }
        band ? band.last : calibration.first.last
      end

      private

      def clause_score(text)
        features(text).sum { |feature| weights[feature] || 0.0 }
      end

      # Word stems and adjacent stem pairs, through the same stemmer the lexicon
      # rails use, so both read the text the same way.
      def features(text)
        words = NLP.words(text).map { |word| NLP.stem(word) }
        (words + words.each_cons(2).map { |pair| pair.join(' ') }).uniq
      end
    end
  end
end
