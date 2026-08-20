# frozen_string_literal: true

# Scores every rail against corpora this repository did not write.
#
#   ruby script/fetch_external.rb && ruby script/measure_external.rb
#
# The shipped corpora have one fatal property: the attacks and the rails were
# written by the same person, so every detection number measures an attacker who
# thought like the defender. That objection cannot be argued away, only
# measured away, which is what this does.
#
# Two sides, two sources.
#
# The context side takes the BIPIA injections and splices them into real
# documentation off this machine, which is the indirect-injection setting as it
# actually arrives: a page somebody else wrote, with a sentence in it that
# somebody else composed. The benign half is the same pages without the
# splicing, so the comparison is paired.
#
# The input side takes the in-the-wild jailbreak prompts and the ordinary
# prompts collected beside them. Both halves are other people's text, scraped
# from where such things circulate, and the benign half is thirteen thousand
# real prompts rather than a handful of sentences somebody composed to be
# tricky.
$LOAD_PATH.unshift(File.expand_path('../lib', __dir__))
require 'json'
require 'vangrail'
require_relative 'local_corpus'
require_relative 'external_corpus'

DATA = ARGV[0] || File.expand_path('../tmp/external', __dir__)
OUTPUT = ARGV[1] || File.expand_path('../tmp/external_results.json', __dir__)
PAGES = (ENV['PAGES'] || 600).to_i
PROMPTS = (ENV['PROMPTS'] || 13_735).to_i

unless File.exist?(File.join(DATA, 'bipia_text_attack_test.json'))
  abort "no corpora in #{DATA}; run: ruby script/fetch_external.rb"
end

# Whatever the builder ships for each side, so a rail added upstream is scored
# the next time this runs. The language rail never blocks and is dropped.
def rails_for(side)
  Vangrail::Builder.deterministic(side).reject { |rail| rail.name == 'language' } +
    [Vangrail::Rails::Bayes.new(sides: [side])]
end

def tally(rails, texts, side)
  counts = rails.to_h { |rail| [rail.name, 0] }
  texts.each_with_index do |text, i|
    warn "    #{i} of #{texts.size}" if i.positive? && (i % 2000).zero?
    rails.each { |rail| counts[rail.name] += 1 if rail.call(text, side: side).blocked? }
  end
  counts
end

def entry_for(name, caught, attacks, flagged, benign)
  Vangrail::Evidence.new(rail: name, group: name, attacks_caught: caught, attacks: attacks,
                         benign_flagged: flagged, benign: benign)
end

report = {}

# --- context side: published injections in other people's documentation ---

warn 'reading local documentation for the context side'
pages = []
LocalCorpus.each_document(limit: PAGES, quiet: true, truncate: 6000) { |text, _p| pages << text }
injections = ExternalCorpus.bipia_injections(DATA)
warn "#{pages.size} pages, #{injections.size} BIPIA injections"

poisoned = injections.each_with_index.map do |injection, i|
  page = pages[i % pages.size]
  half = page.length / 2
  "#{page[0, half]}\n\n#{injection}\n\n#{page[half..]}"
end

rails = rails_for(:context)
warn 'scoring poisoned pages'
caught = tally(rails, poisoned, :context)
warn 'scoring clean pages'
flagged = tally(rails, pages, :context)

report['context'] = {
  'attacks' => poisoned.size, 'benign' => pages.size,
  'source' => 'BIPIA injections spliced into installed man pages',
  'rails' => rails.to_h do |rail|
    entry = entry_for(rail.name, caught[rail.name], poisoned.size, flagged[rail.name], pages.size)
    [rail.name, { 'caught' => caught[rail.name], 'flagged' => flagged[rail.name],
                  'bits' => entry.bits(true).round(2),
                  'bits_defensible' => entry.bits(true, confidence: 0.95).round(2) }]
  end
}

# --- input side: in-the-wild jailbreaks against ordinary prompts ---

jailbreaks = ExternalCorpus.jailbreak_prompts(DATA, PROMPTS)
regular = ExternalCorpus.regular_prompts(DATA, PROMPTS)
warn "#{jailbreaks.size} jailbreak prompts, #{regular.size} ordinary prompts"

rails = rails_for(:input)
warn 'scoring jailbreak prompts'
caught = tally(rails, jailbreaks, :input)
warn 'scoring ordinary prompts'
flagged = tally(rails, regular, :input)

report['input'] = {
  'attacks' => jailbreaks.size, 'benign' => regular.size,
  'source' => 'in-the-wild jailbreak prompts against ordinary prompts from the same collection',
  'rails' => rails.to_h do |rail|
    entry = entry_for(rail.name, caught[rail.name], jailbreaks.size, flagged[rail.name], regular.size)
    [rail.name, { 'caught' => caught[rail.name], 'flagged' => flagged[rail.name],
                  'detection' => entry.detection.round(4), 'false_alarm' => entry.false_alarm.round(4),
                  'bits' => entry.bits(true).round(2),
                  'bits_defensible' => entry.bits(true, confidence: 0.95).round(2) }]
  end
}

File.write(OUTPUT, JSON.pretty_generate(report))

%w[context input].each do |side|
  data = report[side]
  puts
  puts "#{side}: #{data['attacks']} attacks, #{data['benign']} benign (#{data['source']})"
  puts '  rail                       caught  flagged     bits     at 95%'
  data['rails'].each do |name, row|
    puts format('  %-24s %8d %8d %+8.1f %+10.1f', name, row['caught'], row['flagged'], row['bits'],
                row['bits_defensible'])
  end
end
puts
puts "written to #{OUTPUT}"
