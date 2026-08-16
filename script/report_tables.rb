# frozen_string_literal: true

# Prints the tables the documentation quotes, from the measurement files.
#
#   ruby script/report_tables.rb
#
# Numbers in prose rot the moment a rail changes, and hand-copying them is how a
# document ends up claiming something nobody measured. This prints them in the
# shape the pages use, so updating a table is a paste rather than a
# transcription.
require 'json'

TMP = File.expand_path('../tmp', __dir__)

def load(name)
  path = File.join(TMP, name)
  File.exist?(path) ? JSON.parse(File.read(path)) : nil
end

alarms = load('false_alarms.json')
external = load('external_results.json')
union = load('union.json')

if alarms
  puts "* false alarms on #{alarms['documents']} real documents"
  alarms['counts'].sort_by { |_, hits| hits }.each do |name, hits|
    puts format('| =%s= | %d | %.2f%% | %.2f%% |', name, hits, alarms['rates'][name] * 100,
                alarms['bounds'][name] * 100)
  end
  puts
end

if union
  puts format('* the stack drops %.2f%% of real documentation (%d of %d, 95%% bound %.2f%%)',
              union['union_rate'] * 100, union['union_flagged'], union['documents'],
              union['union_bound'] * 100)
  union['correlations'].first(4).each { |pair, value| puts format('  %-46s %+.2f', pair.tr('|', ' '), value) }
  puts
end

external&.each do |side, data|
  puts "* #{side}: #{data['attacks']} attacks, #{data['benign']} benign -- #{data['source']}"
  data['rails'].sort_by { |_, row| -row['bits_defensible'] }.each do |name, row|
    detection = row['caught'].fdiv(data['attacks']) * 100
    false_alarm = row['flagged'].fdiv(data['benign']) * 100
    puts format('| =%s= | %d (%.1f%%) | %d (%.1f%%) | %+.1f |', name, row['caught'], detection,
                row['flagged'], false_alarm, row['bits_defensible'])
  end
  puts
end
