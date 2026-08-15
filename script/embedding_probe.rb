# frozen_string_literal: true

# Calibrates Rails::Semantic against the endpoint you actually use.
#
#   GUARDRAILS_EMBED_MODEL=<model> ruby script/embedding_probe.rb
#
# Not part of `rake test`, which runs offline. A cosine score is a property of
# an embedding model rather than of this gem, so the threshold in the rail is a
# starting point and this is where it becomes a number somebody measured. A
# threshold nobody checked against the model in use is not a defence.
#
# What it prints is a distribution rather than a verdict: the benign corpus's
# top score, the attack corpus's worst score, and the gap between them. A
# threshold belongs in the middle of that gap. When there is no gap, the model
# cannot separate these two sets and the honest conclusion is to leave the rail
# off rather than to pick a number that splits the difference.
#
# Both corpora are the ones the offline suite uses, in English and Dutch, so the
# comparison is against the same text the deterministic rails are scored on.

$LOAD_PATH.unshift(File.expand_path('../lib', __dir__))
$LOAD_PATH.unshift(File.expand_path('../test', __dir__))
require 'vangrail'
require 'test_paraphrase'
require 'test_multilingual'
require 'test_similarity'

provider = Vangrail.provider
abort 'no endpoint resolved: set GUARDRAILS_API_BASE, or start a local proxy' unless provider&.available?
unless provider.embed?
  abort "provider #{provider.name} has no embedding model: set GUARDRAILS_EMBED_MODEL " \
        '(or LLMLITE_EMBED_MODEL for the local proxy)'
end

rail = Vangrail::Rails::Semantic.new(embeddings: provider.embeddings)
puts "endpoint: #{provider.name} #{provider.base_url}"
puts "model:    #{provider.model(:embed)}"
puts "seeds:    #{Vangrail::KnownAttacks::ALL.size}"
puts

BENIGN = (TestParaphrase::BENIGN + TestMultilingual::BENIGN).freeze
ATTACKS = (TestParaphrase::PARAPHRASED + TestMultilingual::ATTACKS + TestSimilarity::EDITED).freeze

def scored(rail, texts)
  texts.map do |text|
    score, seed, = rail.nearest([text])
    { text: text, score: score, seed: seed }
  end
rescue Vangrail::Error => e
  abort "the endpoint did not answer: #{e.message}"
end

benign = scored(rail, BENIGN).sort_by { |row| -row[:score] }
attacks = scored(rail, ATTACKS).sort_by { |row| row[:score] }

def report(title, rows)
  puts title
  rows.first(5).each { |row| puts format('  %<score>.3f  %<text>s', score: row[:score], text: row[:text][0, 66]) }
  puts
end

report("ordinary documentation, highest first (#{benign.size} texts)", benign)
report("attacks, lowest first (#{attacks.size} texts)", attacks)

top = benign.first[:score]
low = attacks.first[:score]
puts format('benign top:  %<top>.3f', top: top)
puts format('attack low:  %<low>.3f', low: low)

if low > top
  puts format('gap:         %<gap>.3f', gap: low - top)
  puts format('threshold:   %<mid>.3f   (the middle of the gap)', mid: (low + top) / 2)
  puts
  puts "GUARDRAILS_RAILS=context,semantic GUARDRAILS_SEMANTIC_THRESHOLD=#{format('%.2f', (low + top) / 2)}"
  puts
  # The threshold is half of what a deployment needs. The other half is what a
  # hit from this rail is worth as evidence, which nothing but a run against
  # this endpoint can say, and which Engine#assess cannot use until it exists.
  threshold = (low + top) / 2
  caught = attacks.count { |row| row[:score] >= threshold }
  flagged = benign.count { |row| row[:score] >= threshold }
  puts 'Add this to your evidence table so the rail can join a posterior:'
  puts format('  Vangrail::Evidence.new(rail: %<rail>p, group: %<rail>p,',
              rail: 'semantic')
  puts format('                         attacks_caught: %<caught>d, attacks: %<attacks>d,',
              caught: caught, attacks: attacks.size)
  puts format('                         benign_flagged: %<flagged>d, benign: %<benign>d)',
              flagged: flagged, benign: benign.size)
else
  puts 'no gap: this model does not separate these two corpora.'
  puts 'Leave the rail off rather than picking a threshold between overlapping sets.'
  overlap = benign.select { |row| row[:score] >= low }
  puts "#{overlap.size} ordinary text(s) score at or above the worst attack, starting with:"
  overlap.first(3).each { |row| puts format('  %<score>.3f  %<text>s', score: row[:score], text: row[:text][0, 66]) }
end
