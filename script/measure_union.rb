# frozen_string_literal: true

# What the whole context stack does to real documentation, and which rails
# agree with each other when the text is not ours.
#
#   ruby script/measure_union.rb [documents] [output.json]
#
# The per-rail counts answer "how often does this rail fire". The question an
# application actually faces is "how much of my corpus does screening throw
# away", and that is the union: a document is dropped if any rail objects. It
# has to be measured rather than added up, because rails that fire on the same
# pages cost less together than their sum suggests.
#
# The same pass gives the correlation between rails on text nobody here wrote.
# The shipped grouping is derived from the hand-written corpus, where no pair
# reached the threshold, and a correlation measured on forty-eight documents
# that all avoid tripping anything is not a correlation.
$LOAD_PATH.unshift(File.expand_path('../lib', __dir__))
require 'json'
require 'vangrail'
require_relative 'local_corpus'

LIMIT = (ARGV[0] || 6000).to_i
OUTPUT = ARGV[1] || File.expand_path('../tmp/union.json', __dir__)

deterministic = [Vangrail::Rails::InjectedInstructions.new,
                 Vangrail::Rails::Jailbreak.new(sides: [:context]),
                 Vangrail::Rails::Paraphrase.new(sides: [:context]),
                 Vangrail::Rails::Similarity.new(sides: [:context]),
                 Vangrail::Rails::ManyShot.new(sides: [:context])]
RAILS = deterministic + [Vangrail::Rails::Obfuscation.new(rails: deterministic, sides: [:context]),
                         Vangrail::Rails::Hidden.new(rails: deterministic)]
NAMES = RAILS.map(&:name).freeze

vectors = []
seen = 0
started = Time.now

LocalCorpus.each_document(limit: LIMIT) do |text, _path|
  seen += 1
  vectors << RAILS.map { |rail| rail.call(text, side: :context).blocked? }
  warn "  #{seen}, #{(Time.now - started).round}s" if (seen % 2000).zero?
end

union = vectors.count { |row| row.any? }
per_rail = NAMES.each_with_index.to_h { |name, i| [name, vectors.count { |row| row[i] }] }

# Phi over the real corpus, which is the number the grouping rule should have
# been reading all along.
def phi(left, right)
  n11 = left.zip(right).count { |a, b| a && b }
  n10 = left.zip(right).count { |a, b| a && !b }
  n01 = left.zip(right).count { |a, b| !a && b }
  n00 = left.zip(right).count { |a, b| !a && !b }
  denominator = Math.sqrt((n11 + n10) * (n01 + n00) * (n11 + n01) * (n10 + n00))
  return 0.0 if denominator.zero?

  ((n11 * n00) - (n10 * n01)) / denominator
end

columns = NAMES.each_with_index.to_h { |name, i| [name, vectors.map { |row| row[i] }] }
correlations = NAMES.combination(2).to_h do |a, b|
  ["#{a}|#{b}", phi(columns[a], columns[b]).round(3)]
end

report = {
  'documents' => seen,
  'union_flagged' => union,
  'union_rate' => union.fdiv(seen).round(5),
  'union_bound' => Vangrail::Beta.quantile(0.95, union + 0.5, seen - union + 0.5).round(5),
  'per_rail' => per_rail,
  'per_rail_rate' => per_rail.transform_values { |hits| hits.fdiv(seen).round(5) },
  'correlations' => correlations.sort_by { |_, value| -value }.to_h
}

File.write(OUTPUT, JSON.pretty_generate(report))

puts format('%<n>d real documents', n: seen)
puts format('screening drops %<u>d of them (%<r>.2f%%), which is what the stack costs a reader',
            u: union, r: report['union_rate'] * 100)
puts
puts 'per rail:'
per_rail.each { |name, hits| puts format('  %-24s %6d  %6.2f%%', name, hits, report['per_rail_rate'][name] * 100) }
puts
puts 'rails that agree, on text nobody here wrote:'
report['correlations'].first(6).each { |pair, value| puts format('  %-50s %+.3f', pair.tr('|', ' '), value) }
puts
puts "written to #{OUTPUT}"
