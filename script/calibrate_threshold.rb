# frozen_string_literal: true

# Picks a threshold for a scoring rail at a false-alarm rate you choose.
#
#   ruby script/fetch_external.rb && ruby script/calibrate_threshold.rb
#
# script/embedding_probe.rb reports the gap between the benign corpus's worst
# score and the attack corpus's best, and refuses to recommend a threshold when
# the two overlap. That rule is honest and it stops helping exactly when help is
# needed, because real corpora always overlap. A deployment still has to choose
# a number, and refusing to choose one means the number gets chosen by whatever
# shipped as a default.
#
# The deployable form of the question is Jacob et al.'s (arXiv:2501.15145): fix
# the false-alarm rate you are willing to pay, find the threshold that produces
# it, and report what the rail catches there. Their case study is the reason to
# bother -- a published detector reads 22.8% of attacks at its default
# threshold and pays 2.9% false alarms for it, and holding it to 1% false alarms
# drops it to 12.8%. Both numbers describe the same model; only the second
# describes a deployment.
#
# Two rules this follows, and the second is that paper's own stated regret:
#
#   AUC is reported and is not the answer. It ranked one detector above another
#   that beat it everywhere below 1% false alarms, which is the only region a
#   deployment ever sits in.
#
#   The threshold is chosen on one half of the benign corpus and reported on the
#   other. Choosing it on the text you then report against is fitting to the
#   test set, and the number that comes out is not the number you will see.
#
#   TARGETS=1,0.5,0.1   false-alarm rates to solve for, in percent
#   PAGES=4000          benign documents to score
$LOAD_PATH.unshift(File.expand_path('../lib', __dir__))
require 'json'
require 'vangrail'
require_relative 'local_corpus'
require_relative 'external_corpus'

DATA = ENV['DATA'] || File.expand_path('../tmp/external', __dir__)
OUTPUT = ENV['OUTPUT'] || File.expand_path('../tmp/calibration.json', __dir__)
PAGES = (ENV['PAGES'] || 4000).to_i
TARGETS = (ENV['TARGETS'] || '1,0.5,0.1').split(',').map { |t| Float(t) / 100.0 }
SEED = (ENV['SEED'] || 11).to_i

abort "no corpora in #{DATA}; run: ruby script/fetch_external.rb" unless File.directory?(DATA)

rail = Vangrail::Rails::Bayes.new(sides: [:context])
abort "#{rail.name} does not score, so there is no threshold to choose" unless rail.quantifies?

warn "reading up to #{PAGES} benign documents"
benign = []
LocalCorpus.each_document(limit: PAGES, quiet: true, truncate: 6000) { |text, _p| benign << text }
abort 'no local documentation found to calibrate against' if benign.empty?

injections = ExternalCorpus.bipia_injections(DATA)
abort 'no BIPIA injections; run: ruby script/fetch_external.rb' if injections.empty?

# The attack side is the same splice the external evaluation scores: a real page
# with a published injection in the middle of it, rather than the injection on
# its own. A rail calibrated on bare attack strings is calibrated on a length
# and a register it will never meet.
random = Random.new(SEED)
attacks = injections.each_with_index.map do |injection, i|
  page = benign[(i * 7) % benign.size]
  half = page.length / 2
  "#{page[0, half]}\n\n#{injection}\n\n#{page[half..]}"
end

shuffled = benign.shuffle(random: random)
half = shuffled.size / 2
calibration = shuffled[0, half]
holdout = shuffled[half..]
warn "#{calibration.size} documents to choose on, #{holdout.size} to report on, #{attacks.size} attacks"

def scores(rail, texts)
  texts.map { |text| rail.score_for(text) }
end

warn 'scoring'
calibration_scores = scores(rail, calibration)
holdout_scores = scores(rail, holdout)
attack_scores = scores(rail, attacks)

# The threshold that lets through all but `target` of the benign scores. A rail
# blocks when the score exceeds its threshold, so the quantile is taken from the
# top: at a 1% target, the threshold is the 99th percentile of benign scores.
def threshold_at(sorted_benign, target)
  return sorted_benign.last.to_f if target <= 0

  index = ((1.0 - target) * (sorted_benign.size - 1)).ceil
  sorted_benign[[index, sorted_benign.size - 1].min].to_f
end

def rate_above(values, threshold)
  return 0.0 if values.empty?

  values.count { |v| v > threshold }.to_f / values.size
end

# Mann-Whitney: the chance a random attack outscores a random benign document.
# Reported because everyone reports it, and read with the warning above.
def auc(attack_scores, benign_scores)
  return 0.0 if attack_scores.empty? || benign_scores.empty?

  sorted = benign_scores.sort
  wins = attack_scores.sum do |a|
    lower = sorted.bsearch_index { |b| b >= a } || sorted.size
    upper = sorted.bsearch_index { |b| b > a } || sorted.size
    lower + ((upper - lower) / 2.0)
  end
  wins / (attack_scores.size.to_f * benign_scores.size)
end

sorted_calibration = calibration_scores.sort
top = sorted_calibration.last.to_f
rows = TARGETS.map do |target|
  threshold = threshold_at(sorted_calibration, target)
  # Named, because "catches 0.00%" is two different findings. A threshold that
  # reaches the target and catches nothing is a useless operating point; a
  # target no threshold reaches short of refusing everything is not an
  # operating point at all. Jacob et al. mark the second case in their own
  # tables rather than printing a zero.
  { 'target_fpr' => target, 'threshold' => threshold.round(4),
    'unreachable' => threshold >= top,
    'fpr_on_holdout' => rate_above(holdout_scores, threshold).round(5),
    'tpr' => rate_above(attack_scores, threshold).round(4) }
end

shipped = rail.threshold
report = {
  'schema' => 'vangrail-calibration-v1', 'rail' => rail.name,
  'benign' => { 'calibration' => calibration.size, 'holdout' => holdout.size },
  'attacks' => attacks.size,
  'auc' => auc(attack_scores, holdout_scores).round(4),
  'shipped' => { 'threshold' => shipped,
                 'fpr_on_holdout' => rate_above(holdout_scores, shipped).round(5),
                 'tpr' => rate_above(attack_scores, shipped).round(4) },
  'operating_points' => rows,
}
File.write(OUTPUT, "#{JSON.pretty_generate(report)}\n")

puts format('%s: AUC %.3f over %d attacks and %d held-out documents',
            rail.name, report['auc'], attacks.size, holdout.size)
puts format('  %-22s threshold %8.3f  false alarms %6.3f%%  catches %6.2f%%',
            'as shipped', shipped, report['shipped']['fpr_on_holdout'] * 100,
            report['shipped']['tpr'] * 100)
rows.each do |row|
  note = row['unreachable'] ? '  (no threshold reaches this target short of blocking nothing)' : ''
  puts format('  at %5.2f%% false alarms  threshold %8.3f  measured %6.3f%%  catches %6.2f%%%s',
              row['target_fpr'] * 100, row['threshold'], row['fpr_on_holdout'] * 100,
              row['tpr'] * 100, note)
end
puts '  the threshold was chosen on one half of the benign corpus and the rates read on the other'
puts "written to #{OUTPUT}"
