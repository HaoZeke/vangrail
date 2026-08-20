# frozen_string_literal: true

# Downloads the published corpora the external evaluation runs against.
#
#   ruby script/fetch_external.rb [directory]
#
# Nothing here is checked in. These are other people's datasets under their own
# licences and terms, they are large, and one of them is a collection of
# in-the-wild jailbreak prompts whose contents are exactly what you would
# expect; a guardrail gem is not the right place to redistribute any of it. The
# scripts fetch, measure, and check in the counts.
#
#   BIPIA           Yi et al., indirect prompt injection benchmark. The attack
#                   strings, which is what a context rail is judged on.
#   jailbreak_llms  Shen et al., in-the-wild jailbreak prompts scraped from the
#                   places they circulate, with a matched set of ordinary
#                   prompts from the same collection. The second half is the
#                   part that matters: a benign corpus somebody else built.
require 'fileutils'
require 'net/http'
require 'uri'

DEST = ARGV[0] || File.expand_path('../tmp/external', __dir__)

SOURCES = {
  'bipia_text_attack_test.json' =>
    'https://raw.githubusercontent.com/microsoft/BIPIA/main/benchmark/text_attack_test.json',
  'bipia_code_attack_test.json' =>
    'https://raw.githubusercontent.com/microsoft/BIPIA/main/benchmark/code_attack_test.json',
  'jailbreak_prompts_2023_12_25.csv' =>
    'https://raw.githubusercontent.com/verazuo/jailbreak_llms/main/data/prompts/jailbreak_prompts_2023_12_25.csv',
  'regular_prompts_2023_12_25.csv' =>
    'https://raw.githubusercontent.com/verazuo/jailbreak_llms/main/data/prompts/regular_prompts_2023_12_25.csv',
}.freeze

FileUtils.mkdir_p(DEST)

SOURCES.each do |name, url|
  path = File.join(DEST, name)
  if File.exist?(path) && File.size(path).positive?
    puts "have #{name} (#{File.size(path) / 1024} KB)"
    next
  end

  print "fetching #{name} ... "
  body = Net::HTTP.get_response(URI(url))
  raise "#{url} answered #{body.code}" unless body.is_a?(Net::HTTPSuccess)

  File.binwrite(path, body.body)
  puts "#{File.size(path) / 1024} KB"
end

puts
puts "into #{DEST}"
puts 'now: ruby script/measure_external.rb'
