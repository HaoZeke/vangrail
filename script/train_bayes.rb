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
# Four disjoint source-group roles keep the result auditable.
#
# Features are selected rather than kept, by mutual information against the
# class, which is what the junk-mail literature did and what keeps a table of a
# few hundred entries instead of tens of thousands.
#
# Counts are smoothed with a Dirichlet prior, so a feature seen only in attacks
# does not make the classifier certain on the strength of three sightings.
#
# The train role fits features and weights. The calibration role maps score
# bands to joint likelihood-ratio bounds. The threshold role chooses the
# operating point. Only the final-test role supplies reported denominators. A
# source group belongs to exactly one role.

$LOAD_PATH.unshift(File.expand_path('../lib', __dir__))
require 'digest'
require 'json'
require 'vangrail'
require_relative 'handbook_corpus'
require_relative 'bayes_training'

module Vangrail
  module BayesTraining
    module_function

    OUT = File.expand_path('../lib/vangrail/bayes_data.rb', __dir__)

    # How many features survive selection. Small on purpose: the corpus is small,
    # and a table with more parameters than documents is a lookup table.
    FEATURES = 300

    # Dirichlet pseudocount per feature per class.
    ALPHA = 1.0

    SPLIT_SEED = 'bayes-v1'

    # Clause-level labels, and the reason is the same one the containment rail ran
    # into. An attack document here is ordinary documentation with one injected
    # sentence in it, so a bag of features over the whole document is mostly
    # evidence about the handbook. Trained and scored per clause, the label matches
    # what is actually being classified, and a document takes the score of its worst
    # clause.
    def attack_clauses
      HandbookCorpus.attack_clauses
    end

    # Documents built the way the threat arrives. Source grouping keeps an
    # evaluation injection out of the fitted feature table.
    def attack_document(injection, index)
      prose = HandbookCorpus::ENGLISH_BENIGN
      "#{prose[index % prose.size]}\n\n#{injection}\n\nSee the reference pages for the full table."
    end

    def benign_documents
      HandbookCorpus.benign_texts
    end

    def training_cases
      attacks = attack_clauses.each_with_index.map do |text, index|
        id = format('attack-%03d', index)
        { id: id, group: id, label: :attack, training_texts: [text],
          document: attack_document(text, index) }
      end
      benign = benign_documents.each_with_index.map do |document, index|
        id = format('benign-%03d', index)
        { id: id, group: id, label: :benign,
          training_texts: Vangrail::NLP.clauses(document).uniq, document: document }
      end
      attacks + benign
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

    # --- calibration, because a naive Bayes score is not a likelihood ratio ---
    #
    # The features are counted as independent and they are nothing of the sort: a
    # word and the pair containing it both vote, so the raw score overstates its own
    # evidence, sometimes by an order of magnitude. That failure is documented as
    # well as any result in this literature, and the standard repair is to fit the
    # map from score to probability on a separate calibration role rather than to
    # trust the model to produce one.
    #
    # Binned rather than a fitted curve, because six calibration attacks cannot
    # support a curve. The bins use the same joint Beta bound as every other
    # operating point in the gem, including zero when the sample cannot defend a
    # direction.
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

    def calibration_bins(predictions)
      unless predictions.all? { |row| row[:role] == :calibration }
        raise ArgumentError, 'calibration requires calibration-role predictions'
      end

      bins = EDGES.each_index.map { |i| { attacks: 0, benign: 0, floor: EDGES[i] } }
      predictions.each do |row|
        key = row[:label] == :attack ? :attacks : :benign
        bins[bin_for(row.fetch(:score))][key] += 1
      end
      n_attack = predictions.count { |row| row[:label] == :attack }
      n_benign = predictions.count { |row| row[:label] == :benign }
      bins = isotonic(bins, n_attack, n_benign)
      bins.each { |bin| bin[:bits] = bits_for(bin, n_attack, n_benign).round(3) }
    end

    def fit_partitions(partitions)
      train_rows = partitions.fetch(:train)
      attack_texts = train_rows.select { |row| row[:label] == :attack }
                               .flat_map { |row| row.fetch(:training_texts) }.uniq
      benign_texts = train_rows.select { |row| row[:label] == :benign }
                               .flat_map { |row| row.fetch(:training_texts) }.uniq
      weights = train(attack_texts, benign_texts)
      predictions = %i[calibration threshold test].to_h do |role|
        [role, predict(partitions, role: role) { |row| score(row.fetch(:document), weights) }]
      end
      threshold = select_threshold(predictions.fetch(:threshold))
      measured = performance(predictions.fetch(:test), threshold: threshold)
      bins = calibration_bins(predictions.fetch(:calibration))
      { attack_texts: attack_texts, benign_texts: benign_texts, weights: weights,
        predictions: predictions, threshold: threshold, performance: measured, calibration: bins }
    end

    def print_report(fit, seed:, output_stream:, error_stream:)
      measured = fit.fetch(:performance)
      bins = fit.fetch(:calibration)
      error_stream.puts "training clauses: #{fit.fetch(:attack_texts).size} attack, " \
                        "#{fit.fetch(:benign_texts).size} benign"
      output_stream.puts format('disjoint split %<seed>s, threshold %<threshold>+d bits',
                                seed: seed, threshold: fit.fetch(:threshold))
      output_stream.puts format('  final-test attacks above threshold: %<caught>d/%<attacks>d', **measured)
      output_stream.puts format('  final-test benign above threshold:  %<flagged>d/%<benign>d', **measured)

      output_stream.puts
      output_stream.puts "calibration-role scores (#{EDGES.size} bands, #{bins.size} after pooling violators):"
      bins.each_with_index do |bin, i|
        ceiling = bins[i + 1] ? bins[i + 1][:floor] : Float::INFINITY
        output_stream.puts format('  %6.1f to %-6.1f  attacks %3d  benign %3d  -> %+.2f bits (95%% joint)',
                                  bin[:floor], ceiling, bin[:attacks], bin[:benign], bin[:bits])
      end
    end

    def role_counts(partitions)
      partitions.transform_values do |rows|
        { attack: rows.count { |row| row[:label] == :attack },
          benign: rows.count { |row| row[:label] == :benign } }
      end
    end

    def calibration_source(bins)
      bins.map do |bin|
        floor = bin[:floor].finite? ? bin[:floor] : '-Float::INFINITY'
        "        [#{floor}, #{bin[:bits]}], # #{bin[:attacks]} attacks, #{bin[:benign]} benign"
      end.join("\n")
    end

    def weights_source(weights)
      weights.sort_by { |_, weight| -weight }
             .map { |feature, weight| "        #{feature.inspect} => #{weight}" }.join(",\n")
    end

    def artifact_source(partitions, fit, seed:)
      attack_texts = fit.fetch(:attack_texts)
      benign_texts = fit.fetch(:benign_texts)
      measured = fit.fetch(:performance)
      threshold = fit.fetch(:threshold)
      calibration_lines = calibration_source(fit.fetch(:calibration))
      entries = weights_source(fit.fetch(:weights))
      counts = role_counts(partitions)

      <<~RUBY
        # frozen_string_literal: true

        module Vangrail
          # Naive Bayes weights over the corpora, in bits per feature.
          #
          # GENERATED FILE. Do not edit by hand; rerun script/train_bayes.rb when a
          # corpus changes. The rail that reads this lives in rails/bayes.rb.
          #
          # #{FEATURES} features selected by mutual information from #{attack_texts.size}
          # attack and #{benign_texts.size} benign training clauses. Cases are
          # source-grouped into disjoint train, calibration, threshold, and final-test
          # roles under split seed #{seed.inspect}. Counts use a Dirichlet prior of
          # #{ALPHA}; weights are log2 class likelihood ratios.
          #
          # The threshold comes only from the threshold role. Final-test performance
          # is #{measured[:caught]} of #{measured[:attacks]} attacks and
          # #{measured[:flagged]} of #{measured[:benign]} benign documents above it.
          module BayesData
            SPLIT_SEED = #{seed.inspect}
            ROLE_COUNTS = #{counts.inspect}.freeze
            THRESHOLD = #{threshold}

            # Score band => bits, fitted only on calibration-role scores and read at
            # the simultaneous 95% likelihood-ratio bound.
            # A raw naive Bayes score is not a likelihood ratio; this is what turns it
            # into one the corpus can defend.
            CALIBRATION = [
        #{calibration_lines}
            ].freeze

            # Final-test performance at THRESHOLD, for the evidence table.
            CAUGHT = #{measured[:caught]}
            ATTACKS = #{measured[:attacks]}
            FLAGGED = #{measured[:flagged]}
            BENIGN = #{measured[:benign]}

            WEIGHTS = {
        #{entries}
            }.freeze
          end
        end
      RUBY
    end

    def default_manifest_path(output)
      "#{output.delete_suffix('.rb')}.manifest.json"
    end

    def manifest_cases(partitions)
      ROLES.flat_map do |role|
        partitions.fetch(role).sort_by { |row| row.fetch(:id) }.map do |row|
          content = JSON.generate(document: row.fetch(:document), training_texts: row.fetch(:training_texts))
          { id: row.fetch(:id), group: row.fetch(:group), label: row.fetch(:label), role: role,
            sha256: Digest::SHA256.hexdigest(content) }
        end
      end
    end

    def manifest_data(output, partitions, fit, seed:)
      {
        schema: 'vangrail-bayes-split-v1',
        split_seed: seed,
        role_weights: ROLE_WEIGHTS,
        role_counts: role_counts(partitions),
        cases: manifest_cases(partitions),
        artifact: {
          file: File.basename(output),
          sha256: Digest::SHA256.file(output).hexdigest,
          features: fit.fetch(:weights).size,
          threshold: fit.fetch(:threshold),
        },
        final_test: fit.fetch(:performance),
      }
    end

    def write_manifest(path, output, partitions, fit, seed:)
      File.write(path, "#{JSON.pretty_generate(manifest_data(output, partitions, fit, seed: seed))}\n")
    end

    def generate(output: OUT, manifest: nil, seed: SPLIT_SEED, output_stream: $stdout, error_stream: $stderr)
      partitions = grouped_partition(training_cases, seed: seed)
      fit = fit_partitions(partitions)
      print_report(fit, seed: seed, output_stream: output_stream, error_stream: error_stream)
      File.write(output, artifact_source(partitions, fit, seed: seed))
      manifest ||= default_manifest_path(output)
      write_manifest(manifest, output, partitions, fit, seed: seed)
      output_stream.puts "wrote #{output}"
      output_stream.puts "wrote #{manifest}"
      fit.merge(partitions: partitions, manifest: manifest)
    end
  end
end

Vangrail::BayesTraining.generate if $PROGRAM_NAME == __FILE__
