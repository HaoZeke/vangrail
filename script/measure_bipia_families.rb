# frozen_string_literal: true

# The context-side result, split by what the attack actually asks for.
#
#   ruby script/measure_bipia_families.rb
#
# The first run of the external evaluation reported zero catches out of 125 for
# every deterministic rail, which reads as total failure and is not what
# happened. BIPIA's text attacks are off-task instructions -- "write a script to
# rename all files in a directory", "analyse the trend of electric car sales" --
# and they contain no override, no disclosure, and no concealment. Every rail
# here is built to find one of those three. A rail that fired on "analyse the
# trend of electric car sales" appearing in a document would be unusable on any
# corpus of documentation ever written.
#
# So the number to report is not one number. It is a coverage map: which
# families of published attack this design can see at all, and which it is blind
# to by construction rather than by accident. The blind one is real and the
# coverage page has never named it.
$LOAD_PATH.unshift(File.expand_path('../lib', __dir__))
require 'json'
require 'vangrail'
require_relative 'local_corpus'
require_relative 'external_corpus'

DATA = ARGV[0] || File.expand_path('../tmp/external', __dir__)
OUTPUT = ARGV[1] || File.expand_path('../tmp/bipia_families.json', __dir__)
PAGES = 120

deterministic = [Vangrail::Rails::InjectedInstructions.new,
                 Vangrail::Rails::Jailbreak.new(sides: [:context]),
                 Vangrail::Rails::Paraphrase.new(sides: [:context]),
                 Vangrail::Rails::Similarity.new(sides: [:context]),
                 Vangrail::Rails::ManyShot.new(sides: [:context])]
RAILS = deterministic + [Vangrail::Rails::Obfuscation.new(rails: deterministic, sides: [:context]),
                         Vangrail::Rails::Hidden.new(rails: deterministic),
                         Vangrail::Rails::Bayes.new(sides: [:context])]

pages = []
LocalCorpus.each_document(limit: PAGES, quiet: true, truncate: 4000) { |text, _p| pages << text }

def splice(page, injection)
  half = page.length / 2
  "#{page[0, half]}\n\n#{injection}\n\n#{page[half..]}"
end

families = {}
%w[bipia_text_attack_test.json bipia_code_attack_test.json].each do |file|
  kind = file.include?('text') ? 'text' : 'code'
  JSON.parse(File.read(File.join(DATA, file))).each do |category, attacks|
    families["#{kind}/#{category}"] = attacks
  end
end

report = {}
families.each_with_index do |(name, attacks), index|
  poisoned = attacks.each_with_index.map { |attack, i| splice(pages[(index + i) % pages.size], attack.to_s) }
  caught = RAILS.to_h do |rail|
    [rail.name, poisoned.count { |text| rail.call(text, side: :context).blocked? }]
  end
  any = poisoned.count { |text| RAILS.any? { |rail| rail.call(text, side: :context).blocked? } }
  report[name] = { 'attacks' => poisoned.size, 'any_rail' => any, 'per_rail' => caught }
end

File.write(OUTPUT, JSON.pretty_generate(report))

puts format('%-42s %8s %10s', 'BIPIA family', 'attacks', 'any rail')
report.sort_by { |_, row| -row['any_rail'].fdiv(row['attacks']) }.each do |name, row|
  puts format('%-42s %8d %10d', name, row['attacks'], row['any_rail'])
end
total = report.values.sum { |row| row['attacks'] }
caught = report.values.sum { |row| row['any_rail'] }
puts format('%-42s %8d %10d  (%.0f%%)', 'all', total, caught, caught.fdiv(total) * 100)
puts
puts 'by rail, over everything:'
RAILS.each do |rail|
  hits = report.values.sum { |row| row['per_rail'][rail.name] }
  puts format('  %-24s %4d/%d', rail.name, hits, total)
end
