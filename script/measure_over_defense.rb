# frozen_string_literal: true

# Scores every input rail against benign questions built to look like attacks.
#
#   ruby script/fetch_external.rb && ruby script/measure_over_defense.rb
#
# The false-alarm rates in the external evaluation come from installed
# documentation, and documentation is an easy benign corpus: almost none of it
# is phrased as a request at all. The questions a desk actually receives are
# requests, and some of them carry the words an injection carries -- somebody
# asking whether they can ignore a compiler warning, or what an uncensored
# model is. A rail cannot fire on those and be usable.
#
# NotInject (Li et al., arXiv:2410.22770) is that corpus: 339 benign questions
# selected for the trigger words detectors learn as shortcuts, in three subsets
# by how many triggers a question carries. The paper's finding is that every
# open-source prompt guard it tested scores under 60% on it, where 50% is a coin
# toss, and it names the cause: the models learn "ignore" straight to a verdict.
#
# The number to read here is per rail and per subset. A rail whose flag rate
# climbs with the trigger count is keying on the words rather than the request,
# and that is visible in three rows where one number hides it.
$LOAD_PATH.unshift(File.expand_path('../lib', __dir__))
require 'json'
require 'vangrail'
require_relative 'external_corpus'

DATA = ENV['DATA'] || File.expand_path('../tmp/external', __dir__)
OUTPUT = ENV['OUTPUT'] || File.expand_path('../tmp/over_defense_results.json', __dir__)

rows = ExternalCorpus.notinject_prompts(DATA)
abort "no NotInject files in #{DATA}; run: ruby script/fetch_external.rb" if rows.empty?

# The shipped input stack, plus the trained rails that are not in it, because the
# question this answers is what each rail costs a reader and Bayes is the one
# an application is most likely to add.
rails = Vangrail::Builder.deterministic(:input).reject { |rail| rail.name == 'language' }
rails += [Vangrail::Rails::Bayes.new(sides: [:input])]

warn "#{rows.size} benign trigger-word questions, #{rails.size} rails"

subsets = rows.map { |row| row[:subset] }.uniq
report = {
  'schema' => 'vangrail-over-defense-v1',
  'source' => 'NotInject (InjecGuard, Li et al.), benign questions carrying injection trigger words',
  'total' => rows.size,
  'rails' => {},
  'stack' => {},
}

flagged_any = Hash.new(0)
examples = Hash.new { |hash, key| hash[key] = [] }

rails.each do |rail|
  counts = Hash.new(0)
  rows.each do |row|
    next unless rail.call(row[:text], side: :input).blocked?

    counts[row[:subset]] += 1
    counts['all'] += 1
    examples[rail.name] << { 'prompt' => row[:text], 'triggers' => row[:triggers] } if examples[rail.name].size < 3
  end
  report['rails'][rail.name] = {
    'flagged' => counts['all'],
    'rate' => (counts['all'].to_f / rows.size).round(4),
    'by_subset' => subsets.to_h { |name| [name, counts[name]] },
    'examples' => examples[rail.name],
  }
end

rows.each do |row|
  next unless rails.any? { |rail| rail.call(row[:text], side: :input).blocked? }

  flagged_any[row[:subset]] += 1
  flagged_any['all'] += 1
end

report['stack'] = {
  'flagged' => flagged_any['all'],
  'rate' => (flagged_any['all'].to_f / rows.size).round(4),
  'by_subset' => subsets.to_h { |name| [name, flagged_any[name]] },
  # The paper's metric, so a number here can be read beside the ones in it.
  'over_defense_accuracy' => ((rows.size - flagged_any['all']).to_f / rows.size).round(4),
}

File.write(OUTPUT, "#{JSON.pretty_generate(report)}\n")

puts format('%-24s %6s %7s   %s', 'rail', 'flag', 'rate', subsets.join('  '))
report['rails'].each do |name, entry|
  puts format('%-24s %6d %6.2f%%   %s', name, entry['flagged'], entry['rate'] * 100,
              subsets.map { |s| format('%3d', entry['by_subset'][s]) }.join('  '))
end
puts format('%-24s %6d %6.2f%%   %s', 'stack', report['stack']['flagged'],
            report['stack']['rate'] * 100,
            subsets.map { |s| format('%3d', report['stack']['by_subset'][s]) }.join('  '))
puts format('over-defense accuracy: %.1f%% (the paper reports every open guard model under 60%%)',
            report['stack']['over_defense_accuracy'] * 100)
puts "written to #{OUTPUT}"
