# frozen_string_literal: true

# Measures every rail's false-alarm rate against real documentation.
#
#   ruby script/measure_false_alarms.rb [limit] [output.json]
#
# This is the number the evidence table has been missing. Its benign side is
# forty-eight hand-written sentences, on which no rail has ever fired, so every
# false-alarm rate in it is a smoothing constant rather than a measurement and
# two rails carry no defensible evidence at all as a result.
#
# The corpus here is the documentation installed on the machine: tens of
# thousands of man pages and readmes, written by people who had never heard of
# this gem, full of exactly the text that makes a guardrail look silly. Shell
# commands, environment variables, security advice, warnings that tell the
# reader to ignore something, and the occasional page that quotes an attack
# because documenting attacks is what security tools do.
#
# Every flagged document is recorded with the rail that flagged it and the span
# it matched, because the count on its own cannot separate a false alarm from
# the corpus genuinely containing an injection. Somebody has to read them, and
# the second script does that with a human at the keyboard.
$LOAD_PATH.unshift(File.expand_path('../lib', __dir__))
require 'json'
require 'vangrail'
require_relative 'local_corpus'

LIMIT = (ARGV[0] || 20_000).to_i
OUTPUT = ARGV[1] || File.expand_path('../tmp/false_alarms.json', __dir__)

deterministic = [Vangrail::Rails::InjectedInstructions.new,
                 Vangrail::Rails::Jailbreak.new(sides: [:context]),
                 Vangrail::Rails::Paraphrase.new(sides: [:context]),
                 Vangrail::Rails::Similarity.new(sides: [:context]),
                 Vangrail::Rails::ManyShot.new(sides: [:context])]
RAILS = deterministic + [Vangrail::Rails::Obfuscation.new(rails: deterministic, sides: [:context]),
                         Vangrail::Rails::Hidden.new(rails: deterministic),
                         Vangrail::Rails::Bayes.new(sides: [:context])]

counts = RAILS.to_h { |rail| [rail.name, 0] }
flagged = Hash.new { |hash, key| hash[key] = [] }
seen = 0
started = Time.now

LocalCorpus.each_document(limit: LIMIT) do |text, path|
  seen += 1
  RAILS.each do |rail|
    result = rail.call(text, side: :context)
    next unless result.blocked?

    counts[rail.name] += 1
    # Enough to judge it by, and bounded so a run over twenty thousand
    # documents does not produce a file nobody can open.
    flagged[rail.name] << { 'path' => path, 'reason' => result.reason.to_s[0, 300] } if flagged[rail.name].size < 60
  end
  warn "  #{seen} documents, #{counts.values.sum} flags, #{(Time.now - started).round}s" if (seen % 2000).zero?
end

elapsed = (Time.now - started).round

report = {
  'documents' => seen,
  'seconds' => elapsed,
  'source' => 'installed man pages and package documentation',
  'counts' => counts,
  'rates' => counts.transform_values { |hits| (hits.fdiv(seen)).round(6) },
  'bounds' => counts.transform_values do |hits|
    Vangrail::Beta.quantile(0.95, hits + 0.5, seen - hits + 0.5).round(6)
  end,
  'flagged' => flagged
}

require 'fileutils'
FileUtils.mkdir_p(File.dirname(OUTPUT))
File.write(OUTPUT, JSON.pretty_generate(report))

puts format('%<n>d real documents in %<s>ds', n: seen, s: elapsed)
puts format('%-24s %8s %10s %12s', 'rail', 'flagged', 'rate', '95% bound')
counts.each do |name, hits|
  puts format('%-24s %8d %10.5f %12.5f', name, hits, report['rates'][name], report['bounds'][name])
end
puts
puts "flagged documents written to #{OUTPUT}; read them before believing any of these are false alarms"
