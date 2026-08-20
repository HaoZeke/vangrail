# frozen_string_literal: true

require 'json'
require_relative 'nlp'
require_relative 'native'

module Vangrail
  # A linear classifier over hashed n-grams, loaded from a file somebody fitted.
  #
  # No weights ship with this gem, and that is the finding rather than an
  # omission. The classifier that does ship, Rails::Bayes, has only thirty
  # attack training clauses and an honestly weak 3/6 detection, 2/6 false-alarm
  # final test; the same architecture fitted on 15,140 real prompts catches three
  # quarters of them. The difference is the corpus, and the corpus has to be the
  # deployment's, because a model fitted on somebody else's traffic is not a
  # measurement of local traffic.
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
    # four-grams are sampled every STRIDE characters. The bucket count and
    # the stride are written into the file; LIMIT stays a process constant.
    # Change the stride and the character-gram indices move.
    LIMIT = 4000
    BUCKETS = 2**18
    STRIDE = 2
    # A hostile file names its own table size. Array.new of that number is
    # the allocation, so the bound has to sit in front of it.
    MAX_BUCKETS = 2**20

    attr_reader :bias, :buckets, :stride, :threshold, :trained_on

    def self.load(path)
      data = JSON.parse(File.read(path))
      buckets = bounded_integer(data['buckets'], name: 'buckets', default: BUCKETS, max: MAX_BUCKETS)
      # Older files have no stride field; they were trained at 2.
      stride = bounded_integer(data['stride'], name: 'stride', default: 2, max: LIMIT)
      weights = Array.new(buckets, 0.0)
      data.fetch('weights').each do |index, value|
        i = index.to_i
        raise ArgumentError, "weight index #{i} is outside #{buckets} buckets" if i.negative? || i >= buckets

        weights[i] = value
      end
      raise ArgumentError, "loaded #{weights.size} weights for #{buckets} buckets" unless weights.size == buckets

      new(weights: weights, bias: data['bias'].to_f, buckets: buckets, stride: stride,
          threshold: data['threshold'], trained_on: data['trained_on'])
    end

    def initialize(weights:, bias: 0.0, buckets: BUCKETS, stride: STRIDE, threshold: nil, trained_on: nil)
      raise ArgumentError, "weights.size (#{weights.size}) != buckets (#{buckets})" unless weights.size == buckets

      @weights = weights
      @bias = bias
      @buckets = buckets
      @stride = stride
      @threshold = threshold
      @trained_on = trained_on
    end

    def self.bounded_integer(value, name:, default:, max:)
      count = value.nil? ? default : value
      unless count.is_a?(Integer) && count.positive? && count <= max
        raise ArgumentError, "#{name} must be an integer between 1 and #{max}, got #{count.inspect}"
      end

      count
    end
    private_class_method :bounded_integer

    # FNV-1a rather than String#hash, which is seeded per process: a model whose
    # feature indices move between runs cannot be saved, and the failure would
    # look like a classifier that trained perfectly and predicts at random.
    def self.bucket(feature, buckets = BUCKETS)
      hash = 2_166_136_261
      feature.each_byte { |byte| hash = ((hash ^ byte) * 16_777_619) & 0xFFFFFFFF }
      hash % buckets
    end

    # Word stems, adjacent stem pairs, and character four-grams taken every
    # stride characters, counted and capped. The cap is what stops a page
    # repeating one word from outvoting a page that says something. Train
    # calls this with the process STRIDE; score calls it with the stride the
    # file named, so the two cannot silently disagree.
    def self.features(text, buckets = BUCKETS, stride = STRIDE)
      _body, words, normalised = prepared(text)
      features_from(words, normalised, buckets, stride)
    end

    def self.prepared(text)
      body = text.to_s[0, LIMIT]
      [body, NLP.words(body).map { |word| NLP.stem(word) }, NLP.normalize(body)]
    end

    # The log-odds the model assigns, positive towards attack. Stemming and
    # Unicode folding stay in Ruby; the hashed bag and the dot product are the
    # native kernel when vangrail-native is loaded.
    def score(text)
      _body, words, normalised = self.class.prepared(text)
      table = native_table
      return table.score(bias, buckets, stride, words, normalised) if table

      score_ruby(words, normalised)
    end

    def ruby_score(text)
      _body, words, normalised = self.class.prepared(text)
      score_ruby(words, normalised)
    end

    def score_ruby(words, normalised)
      self.class.features_from(words, normalised, buckets, stride)
          .sum { |index, value| (@weights[index] || 0.0) * value } + bias
    end
    private :score_ruby

    def self.features_from(words, normalised, buckets, stride)
      grams = words + words.each_cons(2).map { |pair| pair.join(' ') }
      chars = if normalised.length > 4
                (0..(normalised.length - 4)).step(stride).map { |i| "c:#{normalised[i, 4]}" }
              else
                []
              end
      (grams + chars).tally.transform_values { |count| [count, 3].min }
                     .each_with_object(Hash.new(0)) { |(feature, count), acc| acc[bucket(feature, buckets)] += count }
    end

    def native_table
      return @native_table if defined?(@native_table)

      @native_table = Native.available? ? Native::Table.new(@weights) : nil
    end
    private :native_table

    def to_h
      { 'buckets' => buckets, 'stride' => stride, 'bias' => bias, 'threshold' => threshold,
        'trained_on' => trained_on,
        'weights' => @weights.each_with_index.filter_map { |value, i| [i.to_s, value] unless value.zero? }.to_h }
    end
  end
end
