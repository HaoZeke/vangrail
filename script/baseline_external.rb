# frozen_string_literal: true

# A learned baseline on other people's data, compared with the rails at a
# matched false-alarm rate.
#
#   ruby script/baseline_external.rb
#
# "Our rails catch X%" means nothing without something to compare against, and
# comparing detection rates at different false-alarm rates means nothing either.
# So: train the simplest respectable classifier on the external corpus,
# cross-validate it, then set its threshold so that it raises exactly as many
# false alarms as the deterministic rails do, and ask which one catches more.
# Matched false-alarm rate is the only comparison that answers a question
# somebody deploying this would ask.
#
# The classifier is a bag-of-stems naive Bayes: word stems and stem pairs,
# mutual-information feature selection, Dirichlet smoothing, scored over the
# whole prompt. It is not Rails::Bayes (that rail scores the worst clause
# against a calibrated table fitted on the handbook corpus). It is not a
# strong baseline by 2020s standards and it is not meant to be. It is the
# baseline that says whether hand-written lexicons are worth their maintenance
# against ten lines of counting, which is the question the rails have never been
# asked.
#
# What is not here is a model baseline. Llama Guard, PromptGuard, and the
# fine-tuned classifiers are the published state of the art on this task, and
# scoring them needs an endpoint serving them; the harness reads any
# OpenAI-compatible one, and this machine has none running. That gap is a gap,
# and it is named rather than papered over.
$LOAD_PATH.unshift(File.expand_path('../lib', __dir__))
require 'json'
require 'vangrail'
require_relative 'external_corpus'

DATA = ARGV[0] || File.expand_path('../tmp/external', __dir__)
OUTPUT = ARGV[1] || File.expand_path('../tmp/baseline_results.json', __dir__)
FOLDS = 5
FEATURES = 400
ALPHA = 1.0

def features(text)
  words = Vangrail::NLP.words(text).map { |word| Vangrail::NLP.stem(word) }
  (words + words.each_cons(2).map { |pair| pair.join(' ') }).uniq
end

def counts_for(texts)
  texts.each_with_object(Hash.new(0)) do |text, acc|
    features(text).each { |feature| acc[feature] += 1 }
  end
end

def informative(attack_counts, benign_counts, n_attack, n_benign, limit)
  total = n_attack + n_benign
  scores = (attack_counts.keys | benign_counts.keys).map do |feature|
    a = attack_counts[feature]
    b = benign_counts[feature]
    present = a + b
    absent = total - present
    score = 0.0
    [[a, n_attack, present], [n_attack - a, n_attack, absent],
     [b, n_benign, present], [n_benign - b, n_benign, absent]].each do |cell, row, column|
      next if cell <= 0 || row.zero? || column.zero?

      score += cell.fdiv(total) * Math.log2(cell.fdiv(total) / (row.fdiv(total) * column.fdiv(total)))
    end
    [feature, score]
  end
  scores.sort_by { |_, score| -score }.first(limit).map(&:first)
end

def train(attack_texts, benign_texts)
  attack_counts = counts_for(attack_texts)
  benign_counts = counts_for(benign_texts)
  selected = informative(attack_counts, benign_counts, attack_texts.size, benign_texts.size, FEATURES)
  selected.to_h do |feature|
    p_attack = (attack_counts[feature] + ALPHA) / (attack_texts.size + (2 * ALPHA))
    p_benign = (benign_counts[feature] + ALPHA) / (benign_texts.size + (2 * ALPHA))
    [feature, Math.log2(p_attack / p_benign)]
  end
end

def score(text, weights)
  features(text).sum { |feature| weights[feature] || 0.0 }
end

def folds(items, count)
  items.each_with_index.group_by { |_, i| i % count }.values.map { |pairs| pairs.map(&:first) }
end

attacks = ExternalCorpus.jailbreak_prompts(DATA)
benign = ExternalCorpus.regular_prompts(DATA)
warn "#{attacks.size} jailbreak prompts, #{benign.size} ordinary prompts"

# --- the rails, on the same texts ---

rails = Vangrail::Builder.deterministic(:input).reject { |rail| rail.name == 'language' }

def any_block?(rails, text)
  rails.any? { |rail| rail.call(text, side: :input).blocked? }
end

warn 'scoring the rails'
rail_caught = attacks.count { |text| any_block?(rails, text) }
rail_flagged = benign.count { |text| any_block?(rails, text) }
rail_fpr = rail_flagged.fdiv(benign.size)
warn format('rails: %<c>d/%<a>d attacks, %<f>d/%<b>d benign (FPR %<r>.4f)',
            c: rail_caught, a: attacks.size, f: rail_flagged, b: benign.size, r: rail_fpr)

# --- the classifier, cross-validated, thresholded to the same false-alarm rate ---

attack_folds = folds(attacks, FOLDS)
benign_folds = folds(benign, FOLDS)
attack_scores = []
benign_scores = []

FOLDS.times do |i|
  warn "  fold #{i + 1} of #{FOLDS}"
  weights = train(attack_folds.reject.with_index { |_, j| j == i }.flatten,
                  benign_folds.reject.with_index { |_, j| j == i }.flatten)
  attack_scores.concat(attack_folds[i].map { |text| score(text, weights) })
  benign_scores.concat(benign_folds[i].map { |text| score(text, weights) })
end

# The threshold that spends exactly the rails' false-alarm budget, so the two
# detection rates are comparable.
sorted = benign_scores.sort
allowed = (rail_fpr * benign_scores.size).floor
matched = allowed.zero? ? sorted.last + 1e-9 : sorted[[sorted.size - allowed - 1, 0].max]
bag_caught = attack_scores.count { |value| value > matched }
bag_flagged = benign_scores.count { |value| value > matched }

# And the threshold that spends nothing, for the other end of the curve.
strict = sorted.last
strict_caught = attack_scores.count { |value| value > strict }

report = {
  'attacks' => attacks.size, 'benign' => benign.size, 'folds' => FOLDS,
  'source' => 'in-the-wild jailbreak prompts against ordinary prompts from the same collection',
  'rails' => { 'caught' => rail_caught, 'flagged' => rail_flagged,
               'detection' => rail_caught.fdiv(attacks.size).round(4), 'false_alarm' => rail_fpr.round(4) },
  'bag_matched' => { 'threshold' => matched.round(3), 'caught' => bag_caught, 'flagged' => bag_flagged,
                     'detection' => bag_caught.fdiv(attacks.size).round(4),
                     'false_alarm' => bag_flagged.fdiv(benign.size).round(4) },
  'bag_zero_false_alarms' => { 'threshold' => strict.round(3), 'caught' => strict_caught,
                               'detection' => strict_caught.fdiv(attacks.size).round(4) }
}

File.write(OUTPUT, JSON.pretty_generate(report))

puts
puts "#{attacks.size} in-the-wild jailbreaks, #{benign.size} ordinary prompts, #{FOLDS}-fold cross-validation"
puts '  detector                       caught  detection  false alarm'
puts format('  %-28s %8d %10.3f %12.4f', 'rails (hand-written)', rail_caught,
            report['rails']['detection'], report['rails']['false_alarm'])
puts format('  %-28s %8d %10.3f %12.4f', 'bag-of-stems, matched FPR', bag_caught,
            report['bag_matched']['detection'], report['bag_matched']['false_alarm'])
puts format('  %-28s %8d %10.3f %12.4f', 'bag-of-stems, zero FPR', strict_caught,
            report['bag_zero_false_alarms']['detection'], 0.0)
puts
puts "written to #{OUTPUT}"
