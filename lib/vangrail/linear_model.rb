# frozen_string_literal: true

require 'json'
require_relative 'nlp'

module Vangrail
  # A linear classifier over hashed n-grams, loaded from a file somebody fitted.
  #
  # No weights ship with this gem, and that is the finding rather than an
  # omission. The classifier that does ship, Rails::Bayes, was fitted on 48
  # hand-written clauses and catches 15 of 48 held out; the same architecture
  # fitted on 15,140 real prompts catches three quarters of them. The difference
  # is the corpus, and the corpus has to be the deployment's, because a model
  # fitted on somebody else's traffic is the thing this repository spent a long
  # time measuring the cost of.
  #
  # Weights do not compress into a readable table either. Pruning the fitted
  # model to its 20,000 largest weights costs 26 points of detection, because
  # the signal is spread across two hundred thousand of them rather than
  # concentrated in a vocabulary anyone could read. So the shipped artifact is
  # the trainer and the reader; the model is a file a deployment generates and
  # keeps.
  #
  #   ruby script/train_linear.rb --emit model.json
  #   GUARDRAILS_LINEAR_MODEL=model.json GUARDRAILS_RAILS=input,linear
  #
  # Features live here rather than in the trainer, so that fitting and scoring
  # cannot drift apart. A classifier whose training features differ from its
  # serving features by one stemmer revision is a classifier that scores well in
  # every test and badly in production, and nothing about the failure looks like
  # a bug.
  class LinearModel
    # A four-thousand character prefix, hashed into a fixed table. Character
    # four-grams are sampled every STRIDE characters. All three numbers are
    # part of the model: change any and every index moves.
    LIMIT = 4000
    BUCKETS = 2**18
    STRIDE = 2

    attr_reader :bias, :buckets, :threshold, :trained_on

    def self.load(path)
      data = JSON.parse(File.read(path))
      buckets = data['buckets'] || BUCKETS
      weights = Array.new(buckets, 0.0)
      data.fetch('weights').each do |index, value|
        i = index.to_i
        raise ArgumentError, "weight index #{i} is outside #{buckets} buckets" if i.negative? || i >= buckets

        weights[i] = value
      end
      raise ArgumentError, "loaded #{weights.size} weights for #{buckets} buckets" unless weights.size == buckets

      new(weights: weights, bias: data['bias'].to_f, buckets: buckets,
          threshold: data['threshold'], trained_on: data['trained_on'])
    end

    def initialize(weights:, bias: 0.0, buckets: BUCKETS, threshold: nil, trained_on: nil)
      raise ArgumentError, "weights.size (#{weights.size}) != buckets (#{buckets})" unless weights.size == buckets

      @weights = weights
      @bias = bias
      @buckets = buckets
      @threshold = threshold
      @trained_on = trained_on
    end

    # FNV-1a rather than String#hash, which is seeded per process: a model whose
    # feature indices move between runs cannot be saved, and the failure would
    # look like a classifier that trained perfectly and predicts at random.
    def self.bucket(feature, buckets = BUCKETS)
      hash = 2_166_136_261
      feature.each_byte { |byte| hash = ((hash ^ byte) * 16_777_619) & 0xFFFFFFFF }
      hash % buckets
    end

    # Word stems, adjacent stem pairs, and character four-grams taken every
    # STRIDE characters, counted and capped. The cap is what stops a page
    # repeating one word from outvoting a page that says something. Train and
    # serve both call this method, so the stride cannot drift apart.
    def self.features(text, buckets = BUCKETS)
      body = text.to_s[0, LIMIT]
      words = NLP.words(body).map { |word| NLP.stem(word) }
      grams = words + words.each_cons(2).map { |pair| pair.join(' ') }
      normalised = NLP.normalize(body)
      chars = if normalised.length > 4
                (0..(normalised.length - 4)).step(STRIDE).map { |i| "c:#{normalised[i, 4]}" }
              else
                []
              end
      (grams + chars).tally.transform_values { |count| [count, 3].min }
                     .each_with_object(Hash.new(0)) { |(feature, count), acc| acc[bucket(feature, buckets)] += count }
    end

    # The log-odds the model assigns, positive towards attack.
    def score(text)
      self.class.features(text, buckets).sum { |index, value| (@weights[index] || 0.0) * value } + bias
    end

    def to_h
      { 'buckets' => buckets, 'bias' => bias, 'threshold' => threshold, 'trained_on' => trained_on,
        'weights' => @weights.each_with_index.filter_map { |value, i| [i.to_s, value] unless value.zero? }.to_h }
    end
  end
end
