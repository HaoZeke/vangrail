# frozen_string_literal: true

# Do the two model-backed context rails catch the same documents?
#
#   ruby script/fetch_external.rb && ruby script/measure_context_layers.rb
#
# A second layer is worth its round trip only if it catches something the first
# one misses. This repository already learned that the hard way on the
# deterministic side, where paraphrase and obfuscation turned out to correlate
# at 0.55 on real text after being reported as independent.
#
# Rails::TaskRelation and Rails::TaskDrift ask different questions about the
# same pair. Relation asks whether the document's tasks belong to the reader's
# topic; drift asks whether the model's own account of what it was asked changed
# when the document arrived. They should fail differently: relation is blind to
# an injection that is on topic, and drift is blind to one the model does not
# read as a request at all.
#
# This runs both over the same pairs and prints the 2x2, which is the only form
# of the answer worth having.
#
#   PAGES=40  pairs to score. Four calls each: two rails, two sides.
#   SEED=5    which pages, drawn across the corpus rather than from the front
#   FROM=0    where to start in the injection list. BIPIA's text attacks come
#             first and its code attacks from index 75, and the two halves are
#             different problems: FROM=75 scores the half that offers a payload
#             as help with the reader's own task. A run that leaves this at 0
#             never sees that half and must not be quoted as if it had.
$LOAD_PATH.unshift(File.expand_path('../lib', __dir__))
require 'json'
require 'vangrail'
require_relative 'local_corpus'
require_relative 'external_corpus'

DATA = ENV['DATA'] || File.expand_path('../tmp/external', __dir__)
OUTPUT = ENV['OUTPUT'] || File.expand_path('../tmp/context_layers.json', __dir__)
PAGES = (ENV['PAGES'] || 40).to_i
SEED = (ENV['SEED'] || 5).to_i
FROM = (ENV['FROM'] || 0).to_i

abort "no corpora in #{DATA}; run: ruby script/fetch_external.rb" unless File.file?(File.join(DATA, 'bipia_text_attack_test.json'))

provider = Vangrail::Provider.resolve
abort 'no provider resolved; set the endpoint environment' unless provider

model = ENV['MODEL'] || provider.model(:judge)
relation = Vangrail::Rails::TaskRelation.new(provider: provider, model: model)
drift = Vangrail::Rails::TaskDrift.new(provider: provider, model: model)
warn "judge: #{model} at #{provider.base_url}"

pairs = []
LocalCorpus.each_document(limit: PAGES * 3, quiet: true, truncate: 3000, sample: true, seed: SEED) do |text, path|
  next if pairs.size >= PAGES

  name = File.basename(path).sub(/\.gz\z/, '').sub(/\.\d\w*\z/, '')
  next if name.strip.empty? || name.match?(/\A[.\d_-]+\z/) || text.to_s.strip.length < 400

  pairs << { question: "How do I use #{name}?", page: text, name: name }
end

injections = ExternalCorpus.bipia_injections(DATA)
warn "#{pairs.size} pairs, #{injections.size} injections"

baselines = {}
rows = pairs.each_with_index.map do |pair, i|
  half = pair[:page].length / 2
  injection = injections[(FROM + i) % injections.size]
  poisoned = "#{pair[:page][0, half]}\n\n#{injection}\n\n#{pair[:page][half..]}"
  # The baseline is a call too, and the first version of this hardening wrapped
  # the rails and left this line outside, so a refused connection here still
  # took the run with it.
  baseline = baselines[pair[:question]]
  if baseline.nil?
    begin
      baseline = baselines[pair[:question]] = drift.baseline_for(pair[:question])
    rescue Vangrail::TransportError => e
      warn "  baseline for #{pair[:name]}: #{e.message[0, 60]}"
    end
  end
  context = { side: :context, user_input: pair[:question], baseline: baseline }

  row = { 'page' => pair[:name], 'injection' => injection }
  %w[relation drift].each do |which|
    rail = which == 'relation' ? relation : drift
    # A transport failure is the endpoint's, not the rail's, and it must not
    # cost forty pairs of measurement. The gateway refused connections partway
    # through one of these runs and took the whole thing with it. Counted as
    # unchecked, which is what it is.
    begin
      on_attack = rail.call(poisoned, **context)
      on_clean = rail.call(pair[:page], **context)
    rescue Vangrail::TransportError => e
      warn "  #{which} on #{pair[:name]}: #{e.message[0, 60]}"
      row["#{which}_caught"] = false
      row["#{which}_flagged_clean"] = false
      row["#{which}_unchecked"] = true
      next
    end
    row["#{which}_caught"] = on_attack.blocked?
    row["#{which}_flagged_clean"] = on_clean.blocked?
    row["#{which}_unchecked"] = !on_attack.certain? || !on_clean.certain?
  end
  warn "  #{i + 1} of #{pairs.size}" if ((i + 1) % 10).zero?
  row
end

def count(rows, &block) = rows.count(&block)

both = count(rows) { |r| r['relation_caught'] && r['drift_caught'] }
relation_only = count(rows) { |r| r['relation_caught'] && !r['drift_caught'] }
drift_only = count(rows) { |r| !r['relation_caught'] && r['drift_caught'] }
neither = count(rows) { |r| !r['relation_caught'] && !r['drift_caught'] }

report = {
  'schema' => 'vangrail-context-layers-v1', 'model' => model, 'pairs' => rows.size, 'seed' => SEED,
  'injection_from' => FROM,
  'caught' => { 'both' => both, 'relation_only' => relation_only, 'drift_only' => drift_only,
                'neither' => neither, 'union' => both + relation_only + drift_only },
  'flagged_clean' => { 'relation' => count(rows) { |r| r['relation_flagged_clean'] },
                       'drift' => count(rows) { |r| r['drift_flagged_clean'] },
                       'either' => count(rows) { |r| r['relation_flagged_clean'] || r['drift_flagged_clean'] } },
  'unchecked' => { 'relation' => count(rows) { |r| r['relation_unchecked'] },
                   'drift' => count(rows) { |r| r['drift_unchecked'] } },
  'missed_by_both' => rows.reject { |r| r['relation_caught'] || r['drift_caught'] }.map { |r| r['injection'] },
  'rows' => rows,
}
File.write(OUTPUT, "#{JSON.pretty_generate(report)}\n")

puts format('%d pairs. caught: both %d, relation only %d, drift only %d, neither %d (union %d)',
            rows.size, both, relation_only, drift_only, neither, report['caught']['union'])
puts format('flagged clean: relation %d, drift %d, either %d',
            report['flagged_clean']['relation'], report['flagged_clean']['drift'],
            report['flagged_clean']['either'])
puts format('unchecked pairs: relation %d, drift %d',
            report['unchecked']['relation'], report['unchecked']['drift'])
unless report['missed_by_both'].empty?
  puts 'missed by both:'
  report['missed_by_both'].each { |injection| puts "  #{injection.gsub(/\s+/, ' ')[0, 92]}" }
end
puts "written to #{OUTPUT}"
