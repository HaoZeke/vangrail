# frozen_string_literal: true

# Trains a linear classifier on the external corpus and scores it against the
# rails and against naive Bayes at a matched false-alarm rate.
#
#   ruby script/train_linear.rb
#
# Naive Bayes lost four bits to its own independence assumption here: a word and
# the pair containing it both vote, so the score overstates itself and has to be
# calibrated after the fact. A discriminative model does not have that problem
# by construction -- it fits the weights jointly, so a feature that repeats
# information already carried gets less of the credit rather than a second vote.
# The generative-versus-discriminative trade is old and well understood: naive
# Bayes converges faster with little data, logistic regression wins once there
# is enough, and 15,140 labelled prompts is enough.
#
# Hashed features, because a vocabulary is a thing to maintain and a hash is
# not. Word unigrams, word bigrams, and character four-grams into a fixed table,
# which is the bag-of-tricks recipe and keeps the shipped model a flat array.
#
# AdaGrad rather than a fixed learning rate: the features are wildly unequal in
# frequency, and a per-feature rate is what stops the common ones from drowning
# the informative rare ones.
#
# Everything reported is cross-validated. The training score is not printed,
# because it is not evidence of anything.
$LOAD_PATH.unshift(File.expand_path('../lib', __dir__))
require 'json'
require 'vangrail'
require_relative 'external_corpus'

DATA = ARGV[0] || File.expand_path('../tmp/external', __dir__)
OUTPUT = ARGV[1] || File.expand_path('../tmp/linear_results.json', __dir__)

BUCKETS = 2**18
EPOCHS = 4
L2 = 1e-6
RATE = 0.5
FOLDS = 5

# FNV-1a rather than String#hash, which is seeded per process: a model whose
# feature indices change between runs is a model that cannot be shipped, and the
# failure would look like a classifier that scores perfectly in training and
# randomly everywhere else.
def bucket(feature)
  hash = 2_166_136_261
  feature.each_byte { |byte| hash = ((hash ^ byte) * 16_777_619) & 0xFFFFFFFF }
  hash % BUCKETS
end

# Truncated, because the tail of a four-thousand-character prompt says little
# the head did not and the cost is linear in every one of them.
LIMIT = 4000

def features(text)
  body = text.to_s[0, LIMIT]
  words = Vangrail::NLP.words(body).map { |word| Vangrail::NLP.stem(word) }
  grams = words + words.each_cons(2).map { |pair| pair.join(' ') }
  normalised = Vangrail::NLP.normalize(body)
  chars = normalised.length > 4 ? (0..(normalised.length - 4)).step(2).map { |i| "c:#{normalised[i, 4]}" } : []
  # Counts rather than presence, capped: a page repeating a word forty times is
  # not forty times the evidence, and the cap is what stops length alone from
  # dominating the score.
  (grams + chars).tally.transform_values { |count| [count, 3].min }
                 .transform_keys { |feature| bucket(feature) }
end

def score(vector, weights, bias)
  vector.sum { |index, value| weights[index] * value } + bias
end

def sigmoid(value)
  return 0.0 if value < -30
  return 1.0 if value > 30

  1.0 / (1.0 + Math.exp(-value))
end

# Weighted for the imbalance: ordinary prompts outnumber attacks ten to one, and
# an unweighted fit learns to say "ordinary" and take the ninety percent.
def train(rows, positive_weight)
  weights = Array.new(BUCKETS, 0.0)
  history = Array.new(BUCKETS, 1e-8)
  bias = 0.0
  bias_history = 1e-8

  EPOCHS.times do
    rows.shuffle(random: Random.new(7)).each do |vector, label|
      predicted = sigmoid(score(vector, weights, bias))
      weight = label == 1 ? positive_weight : 1.0
      error = (predicted - label) * weight

      vector.each do |index, value|
        gradient = (error * value) + (L2 * weights[index])
        history[index] += gradient * gradient
        weights[index] -= RATE * gradient / Math.sqrt(history[index])
      end
      bias_history += error * error
      bias -= RATE * error / Math.sqrt(bias_history)
    end
  end
  [weights, bias]
end

def folds(items, count)
  items.each_with_index.group_by { |_, i| i % count }.values.map { |pairs| pairs.map(&:first) }
end

attacks = ExternalCorpus.jailbreak_prompts(DATA)
benign = ExternalCorpus.regular_prompts(DATA)
warn "#{attacks.size} jailbreak prompts, #{benign.size} ordinary prompts"

warn 'extracting features'
attack_rows = attacks.map { |text| [features(text), 1] }
benign_rows = benign.map { |text| [features(text), 0] }
positive_weight = benign_rows.size.fdiv(attack_rows.size)

attack_folds = folds(attack_rows, FOLDS)
benign_folds = folds(benign_rows, FOLDS)
attack_scores = []
benign_scores = []

FOLDS.times do |i|
  warn "  fold #{i + 1} of #{FOLDS}"
  training = attack_folds.reject.with_index { |_, j| j == i }.flatten(1) +
             benign_folds.reject.with_index { |_, j| j == i }.flatten(1)
  weights, bias = train(training, positive_weight)
  attack_scores.concat(attack_folds[i].map { |vector, _| score(vector, weights, bias) })
  benign_scores.concat(benign_folds[i].map { |vector, _| score(vector, weights, bias) })
end

# The rails' operating point, so the comparison is at one false-alarm rate
# rather than at two.
rails = Vangrail::Builder.deterministic(:input).reject { |rail| rail.name == 'language' }
rail_caught = attacks.count { |text| rails.any? { |rail| rail.call(text, side: :input).blocked? } }
rail_flagged = benign.count { |text| rails.any? { |rail| rail.call(text, side: :input).blocked? } }
rail_fpr = rail_flagged.fdiv(benign.size)

sorted = benign_scores.sort
allowed = (rail_fpr * benign_scores.size).floor
matched = allowed.zero? ? sorted.last : sorted[[sorted.size - allowed - 1, 0].max]
caught = attack_scores.count { |value| value > matched }

# And the operating point a desk would actually want: one false alarm in a
# hundred, which is where the rails cannot go at all.
strict = sorted[(sorted.size * 0.99).floor]
strict_caught = attack_scores.count { |value| value > strict }

report = {
  'attacks' => attacks.size, 'benign' => benign.size, 'folds' => FOLDS, 'buckets' => BUCKETS,
  'rails' => { 'caught' => rail_caught, 'detection' => rail_caught.fdiv(attacks.size).round(4),
               'false_alarm' => rail_fpr.round(4) },
  'linear_matched' => { 'caught' => caught, 'detection' => caught.fdiv(attacks.size).round(4),
                        'false_alarm' => rail_fpr.round(4) },
  'linear_one_percent' => { 'caught' => strict_caught,
                            'detection' => strict_caught.fdiv(attacks.size).round(4),
                            'false_alarm' => 0.01 }
}
File.write(OUTPUT, JSON.pretty_generate(report))

puts
puts "#{attacks.size} in-the-wild jailbreaks, #{benign.size} ordinary prompts, #{FOLDS}-fold cross-validation"
puts format('  %-34s %8s %10s %12s', 'detector', 'caught', 'detection', 'false alarm')
puts format('  %-34s %8d %10.3f %12.4f', 'rails (hand-written)', rail_caught,
            report['rails']['detection'], rail_fpr)
puts format('  %-34s %8d %10.3f %12.4f', 'linear, matched false-alarm rate', caught,
            report['linear_matched']['detection'], rail_fpr)
puts format('  %-34s %8d %10.3f %12.4f', 'linear, one false alarm in a hundred', strict_caught,
            report['linear_one_percent']['detection'], 0.01)
