# frozen_string_literal: true

# Trains lib/vangrail/bayes_data.rb: a naive Bayes classifier over the corpora,
# in the oldest tradition there is.
#
#   ruby script/train_bayes.rb
#
# Every other rail in this gem answers yes or no, which hands the evidence
# arithmetic exactly one bit per rail however sure the rail was. A naive Bayes
# classifier over n-grams answers with a log-likelihood ratio directly, which is
# the quantity the arithmetic actually wants, and it is the technique spam
# filtering settled on decades ago for the same reason: many weak indicators,
# each nearly worthless, adding up.
#
# Three things keep it honest, and the third is the one that decides whether the
# rail ships at all.
#
# Features are selected rather than kept, by mutual information against the
# class, which is what the junk-mail literature did and what keeps a table of a
# few hundred entries instead of tens of thousands.
#
# Counts are smoothed with a Dirichlet prior, so a feature seen only in attacks
# does not make the classifier certain on the strength of three sightings.
#
# And the score reported below is cross-validated, never the training score. A
# classifier fitted to 318 documents and evaluated on the same 318 is a
# memoriser with a good opinion of itself, and the whole point of putting a
# number in the README is that somebody can believe it.

$LOAD_PATH.unshift(File.expand_path('../lib', __dir__))
require 'vangrail'
require_relative 'handbook_corpus'

OUT = File.expand_path('../lib/vangrail/bayes_data.rb', __dir__)

# How many features survive selection. Small on purpose: the corpus is small,
# and a table with more parameters than documents is a lookup table.
FEATURES = 300

# Dirichlet pseudocount per feature per class.
ALPHA = 1.0

FOLDS = 5

# Clause-level labels, and the reason is the same one the containment rail ran
# into. An attack document here is ordinary documentation with one injected
# sentence in it, so a bag of features over the whole document is mostly
# evidence about the handbook. Trained and scored per clause, the label matches
# what is actually being classified, and a document takes the score of its worst
# clause.
def attack_clauses
  HandbookCorpus.attack_clauses
end

def benign_clauses
  HandbookCorpus.benign_texts.flat_map { |text| Vangrail::NLP.clauses(text) }.uniq
end

# Documents built the way the threat arrives, from injections the fold under
# test never trained on.
def attack_documents(injections)
  prose = HandbookCorpus::ENGLISH_BENIGN
  injections.each_with_index.map do |injection, i|
    "#{prose[i % prose.size]}\n\n#{injection}\n\nSee the reference pages for the full table."
  end
end

def benign_documents
  HandbookCorpus.benign_texts
end

# Words and adjacent word pairs, stemmed through the same function the lexicon
# rails use, so the two read the same text the same way.
def features(text)
  words = Vangrail::NLP.words(text).map { |w| Vangrail::NLP.stem(w) }
  (words + words.each_cons(2).map { |pair| pair.join(' ') }).tally
end

def counts_for(documents)
  documents.each_with_object(Hash.new(0)) do |text, acc|
    features(text).each_key { |feature| acc[feature] += 1 }
  end
end

# Mutual information between "text contains this feature" and the class, which
# is the selection criterion the junk-mail work used.
def informative(attack_counts, benign_counts, n_attack, n_benign, limit)
  total = n_attack + n_benign
  scores = (attack_counts.keys | benign_counts.keys).to_h do |feature|
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

def weights_for(selected, attack_counts, benign_counts, n_attack, n_benign)
  selected.to_h do |feature|
    p_attack = (attack_counts[feature] + ALPHA) / (n_attack + (2 * ALPHA))
    p_benign = (benign_counts[feature] + ALPHA) / (n_benign + (2 * ALPHA))
    [feature, Math.log2(p_attack / p_benign).round(4)]
  end
end

def train(attack_texts, benign_texts)
  attack_counts = counts_for(attack_texts)
  benign_counts = counts_for(benign_texts)
  selected = informative(attack_counts, benign_counts, attack_texts.size, benign_texts.size, FEATURES)
  weights_for(selected, attack_counts, benign_counts, attack_texts.size, benign_texts.size)
end

def clause_score(text, weights)
  features(text).keys.sum { |feature| weights[feature] || 0.0 }
end

# A document is as suspicious as its worst clause. Summing instead would let a
# long page dilute an injection, which is the failure this whole design keeps
# running into.
def score(text, weights)
  clauses = Vangrail::NLP.clauses(text)
  return clause_score(text, weights) if clauses.empty?

  clauses.map { |clause| clause_score(clause, weights) }.max
end

# --- cross-validated, because the training score means nothing ---

def folds(documents, count)
  documents.each_with_index.group_by { |_, i| i % count }.values.map { |pairs| pairs.map(&:first) }
end

# --- calibration, because a naive Bayes score is not a likelihood ratio ---
#
# The features are counted as independent and they are nothing of the sort: a
# word and the pair containing it both vote, so the raw score overstates its own
# evidence, sometimes by an order of magnitude. That failure is documented as
# well as any result in this literature, and the standard repair is to fit the
# map from score to probability on held-out data rather than to trust the model
# to produce one.
#
# Binned rather than a fitted curve, because 48 held-out attacks cannot support
# a curve, and the bins are read back through the same Beta bound as every other
# operating point in the gem. That caps what this rail can claim at whatever the
# corpus can defend, which for a corpus this size is a few bits.
EDGES = [-Float::INFINITY, 0.0, 4.0, 8.0, 12.0].freeze

def bin_for(value)
  EDGES.rindex { |edge| value > edge } || 0
end

def bits_for(bin, n_attack, n_benign)
  Vangrail::Evidence.new(rail: 'bayes', attacks_caught: bin[:attacks], attacks: n_attack,
                         benign_flagged: bin[:benign], benign: n_benign).bits(true, confidence: 0.95)
end

# Pool adjacent violators. A calibration map has to be monotone -- a higher
# score cannot mean less evidence -- and with counts this small the raw bins are
# not, because nine attacks against one benign document is noise around ten
# against none. Merging the offending neighbours is the standard isotonic
# repair, and it also says something true: the corpus cannot tell those bands
# apart.
def isotonic(bins, n_attack, n_benign)
  loop do
    index = (0...(bins.size - 1)).detect do |i|
      bits_for(bins[i], n_attack, n_benign) > bits_for(bins[i + 1], n_attack, n_benign)
    end
    break bins if index.nil?

    merged = { floor: bins[index][:floor],
               attacks: bins[index][:attacks] + bins[index + 1][:attacks],
               benign: bins[index][:benign] + bins[index + 1][:benign] }
    bins = bins[0...index] + [merged] + bins[(index + 2)..]
  end
end

def run_trainer
  attack_texts = attack_clauses
  benign_texts = benign_clauses
  warn "attack clauses: #{attack_texts.size}, benign clauses: #{benign_texts.size}"

  attack_folds = folds(attack_texts, FOLDS)
  benign_folds = folds(benign_texts, FOLDS)
  held_out = { attack: [], benign: [] }

  FOLDS.times do |i|
    weights = train(attack_folds.reject.with_index { |_, j| j == i }.flatten,
                    benign_folds.reject.with_index { |_, j| j == i }.flatten)
    held_out[:attack].concat(attack_documents(attack_folds[i]).map { |text| score(text, weights) })
    held_out[:benign].concat(benign_documents.map { |text| score(text, weights) })
  end

  sorted_benign = held_out[:benign].sort
  threshold = sorted_benign.last.ceil
  caught = held_out[:attack].count { |value| value > threshold }
  flagged = held_out[:benign].count { |value| value > threshold }

  puts format('cross-validated over %<folds>d folds, threshold %<threshold>+d bits', folds: FOLDS,
                                                                                     threshold: threshold)
  puts format('  attacks above threshold: %<caught>d/%<total>d', caught: caught, total: held_out[:attack].size)
  puts format('  benign above threshold:  %<flagged>d/%<total>d', flagged: flagged,
                                                                        total: held_out[:benign].size)
  puts format('  attack scores:  median %<median>+.1f, min %<min>+.1f',
              median: held_out[:attack].sort[held_out[:attack].size / 2], min: held_out[:attack].min)
  puts format('  benign scores:  median %<median>+.1f, max %<max>+.1f',
              median: sorted_benign[sorted_benign.size / 2], max: sorted_benign.last)

  bins = EDGES.each_index.map { |i| { attacks: 0, benign: 0, floor: EDGES[i] } }
  held_out[:attack].each { |value| bins[bin_for(value)][:attacks] += 1 }
  held_out[:benign].each { |value| bins[bin_for(value)][:benign] += 1 }
  n_attack = held_out[:attack].size
  n_benign = held_out[:benign].size
  raw_bins = bins.size
  bins = isotonic(bins, n_attack, n_benign)

  puts
  puts "calibration on held-out scores (#{raw_bins} bands, #{bins.size} after pooling violators):"
  bins.each_with_index do |bin, i|
    ceiling = bins[i + 1] ? bins[i + 1][:floor] : Float::INFINITY
    bin[:bits] = bits_for(bin, n_attack, n_benign).round(3)
    puts format('  %6.1f to %-6.1f  attacks %3d  benign %3d  -> %+.2f bits (95%% defensible)',
                bin[:floor], ceiling, bin[:attacks], bin[:benign], bin[:bits])
  end

  weights = train(attack_texts, benign_texts)
  calibration_lines = bins.map do |bin|
    floor = bin[:floor].finite? ? bin[:floor] : '-Float::INFINITY'
    "        [#{floor}, #{bin[:bits]}], # #{bin[:attacks]} attacks, #{bin[:benign]} benign"
  end
  entries = weights.sort_by { |_, weight| -weight }.map do |feature, weight|
    "        #{feature.inspect} => #{weight}"
  end

  File.write(OUT, <<~RUBY)
    # frozen_string_literal: true

    module Vangrail
      # Naive Bayes weights over the corpora, in bits per feature.
      #
      # GENERATED FILE. Do not edit by hand; rerun script/train_bayes.rb when a
      # corpus changes. The rail that reads this lives in rails/bayes.rb.
      #
      # #{FEATURES} features selected by mutual information from #{attack_texts.size}
      # attack and #{benign_texts.size} benign
      # clauses, counted as word stems and adjacent stem pairs, smoothed with a
      # Dirichlet prior of #{ALPHA}. A weight is log2 of how much likelier the feature is
      # in an attack than in ordinary documentation.
      #
      # Cross-validated over #{FOLDS} folds at a threshold of #{threshold} bits:
      # #{caught} of #{n_attack} attacks above it, #{flagged} of #{n_benign}
      # benign documents above it. That number is the held-out one; the training
      # score is not reported because it is not evidence of anything.
      module BayesData
        THRESHOLD = #{threshold}

        # Score band => bits, fitted on held-out scores and read at the 95% bound.
        # A raw naive Bayes score is not a likelihood ratio; this is what turns it
        # into one the corpus can defend.
        CALIBRATION = [
    #{calibration_lines.join("\n")}
        ].freeze

        # Held-out performance at THRESHOLD, for the evidence table.
        CAUGHT = #{caught}
        ATTACKS = #{n_attack}
        FLAGGED = #{flagged}
        BENIGN = #{n_benign}

        WEIGHTS = {
    #{entries.join(",\n")}
        }.freeze
      end
    end
  RUBY

  puts "wrote #{OUT}"
end

run_trainer if $PROGRAM_NAME == __FILE__
