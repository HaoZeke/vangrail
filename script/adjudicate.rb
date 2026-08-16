# frozen_string_literal: true

# Shows the span that tripped each rail, so a person can say whether it was
# wrong.
#
#   ruby script/adjudicate.rb [results.json] [rail] [count]
#
# A flag count is not a false-alarm count. Documentation about security quotes
# attacks, manual pages describe options that ignore previous settings, and a
# corpus of twenty thousand real documents may genuinely contain a page that
# tells an assistant what to do. Deciding which is which is the part that cannot
# be automated, and this is the tool for doing it: for every flagged document it
# re-runs the rail clause by clause and prints the clause that tripped it.
#
# The base rate this repository has been assuming comes out of this step. Every
# flagged document that a reader confirms as a genuine injection is a real
# instance in a known denominator; every one they reject is a false alarm.
$LOAD_PATH.unshift(File.expand_path('../lib', __dir__))
require 'json'
require 'vangrail'
require_relative 'local_corpus'

RESULTS = ARGV[0] || File.expand_path('../tmp/false_alarms.json', __dir__)
ONLY = ARGV[1]
COUNT = (ARGV[2] || 12).to_i

report = JSON.parse(File.read(RESULTS))

# Built from whatever the builder ships, so a rail added upstream can still be
# read rather than silently printing no span.
RAILS = (Vangrail::Builder.deterministic(:context) +
         [Vangrail::Rails::Bayes.new(sides: [:context])]).to_h { |rail| [rail.name, rail] }.freeze

def offending(rail, text)
  clauses = Vangrail::NLP.clauses(text)
  hit = clauses.find { |clause| rail.call(clause, side: :context).blocked? }
  return hit.gsub(/\s+/, ' ')[0, 200] if hit

  # A rail that only fires on the whole document is reporting something about
  # its structure rather than about a sentence, which is worth seeing as such.
  '(fires on the document, not on any single clause)'
end

report['flagged'].each do |rail_name, entries|
  next if ONLY && rail_name != ONLY
  next if entries.empty?

  rail = RAILS[rail_name]
  puts
  puts "=== #{rail_name}: #{report['counts'][rail_name]} of #{report['documents']} documents " \
       "(#{(report['rates'][rail_name] * 100).round(2)}%)"
  entries.first(COUNT).each do |entry|
    puts "--- #{entry['path'].sub('/usr/share/', '')}"
    puts "    reason: #{entry['reason'][0, 160]}"
    next unless rail

    text = LocalCorpus.render(entry['path'])
    puts "    span:   #{text ? offending(rail, text[0, 20_000]) : '(unreadable)'}"
  end
end
