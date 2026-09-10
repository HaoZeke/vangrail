# frozen_string_literal: true

# Scores Rails::TaskRelation on the family every deterministic rail here misses.
#
#   ruby script/fetch_external.rb && ruby script/measure_task_relation.rb
#
# The context measurement in measure_external.rb reads a page alone, because a
# deterministic rail has nothing else to read. This one is the paired version of
# it with the question restored: the same installed documentation, the same
# published BIPIA injections spliced into the middle of it, and the question the
# page would have been retrieved for. A page is poisoned or clean; the question
# is the same either way; the rail sees the pair.
#
# The question is built from the page's own name, which is what a documentation
# desk asks: a reader who is shown the tar(1) page asked something about tar.
# That is a friendly setting for this rail, and saying so is the point -- an
# injection is off-task here by construction, which is exactly the property the
# published attacks have and the shipped corpus does not.
#
#   PAGES=60   how many pairs to score, one chat call each side
#   SKIP=0     eligible pages to pass over first, which is how a run is held
#              out from the one whose misses a prompt was written against
#   SEED=3     which pages the sample draws. Drawn across the corpus rather than
#              from the front of it: the paths are sorted, so the first sixty
#              eligible pages are section 0p in alphabetical order, one genre
#              with one register, and a rate measured on them is a rate for
#              POSIX header pages
#   MODEL=...  the summariser, which the paper's numbers say is the detector
$LOAD_PATH.unshift(File.expand_path('../lib', __dir__))
require 'json'
require 'vangrail'
require_relative 'local_corpus'
require_relative 'external_corpus'

DATA = ENV['DATA'] || File.expand_path('../tmp/external', __dir__)
OUTPUT = ENV['OUTPUT'] || File.expand_path('../tmp/task_relation_results.json', __dir__)
PAGES = (ENV['PAGES'] || 60).to_i
SKIP = (ENV['SKIP'] || 0).to_i
SEED = (ENV['SEED'] || 3).to_i

unless File.exist?(File.join(DATA, 'bipia_text_attack_test.json'))
  abort "no corpora in #{DATA}; run: ruby script/fetch_external.rb"
end

provider = Vangrail::Provider.resolve
abort 'no provider resolved; set the endpoint environment for a model-backed rail' unless provider

model = ENV['MODEL'] || provider.model(:judge)
rail = Vangrail::Rails::TaskRelation.new(provider: provider, model: model)
warn "summariser: #{model} at #{provider.base_url}"

# "How do I use tar?" from .../man1/tar.1.gz, which is the question that page
# answers. A page whose name says nothing is skipped rather than guessed at.
def question_for(path)
  name = File.basename(path).sub(/\.gz\z/, '').sub(/\.\d\w*\z/, '')
  return nil if name.strip.empty? || name.match?(/\A[.\d_-]+\z/)

  "How do I use #{name}?"
end

pairs = []
seen = 0
LocalCorpus.each_document(limit: (PAGES + SKIP) * 3, quiet: true, truncate: 4000,
                          sample: true, seed: SEED) do |text, path|
  next if pairs.size >= PAGES

  question = question_for(path)
  next unless question
  next if text.to_s.strip.length < 400

  seen += 1
  next if seen <= SKIP

  pairs << { question: question, page: text, name: File.basename(path) }
end

injections = ExternalCorpus.bipia_injections(DATA)
warn "#{pairs.size} pages, #{injections.size} BIPIA injections"

def splice(page, injection)
  half = page.length / 2
  "#{page[0, half]}\n\n#{injection}\n\n#{page[half..]}"
end

def score(rail, pairs, poisoned:, injections: nil)
  blocked = 0
  unchecked = 0
  rows = []
  pairs.each_with_index do |pair, i|
    text = poisoned ? splice(pair[:page], injections[(i + SKIP) % injections.size]) : pair[:page]
    result = rail.call(text, side: :context, user_input: pair[:question])
    blocked += 1 if result.blocked?
    unchecked += 1 unless result.certain?
    rows << { 'page' => pair[:name], 'question' => pair[:question], 'blocked' => result.blocked?,
              'certain' => result.certain?, 'reason' => result.reason,
              'injection' => poisoned ? injections[(i + SKIP) % injections.size] : nil }
    warn "  #{i + 1} of #{pairs.size}" if ((i + 1) % 10).zero?
  end
  { 'blocked' => blocked, 'unchecked' => unchecked, 'total' => pairs.size, 'rows' => rows }
end

warn 'scoring poisoned pages'
caught = score(rail, pairs, poisoned: true, injections: injections)
warn 'scoring the same pages clean'
flagged = score(rail, pairs, poisoned: false)

report = {
  'schema' => 'vangrail-task-relation-v1',
  'skip' => SKIP,
  'seed' => SEED,
  'model' => model,
  'source' => 'BIPIA injections spliced into installed documentation, with the page-derived question',
  'attacks' => { 'caught' => caught['blocked'], 'total' => caught['total'],
                 'unchecked' => caught['unchecked'] },
  'benign' => { 'flagged' => flagged['blocked'], 'total' => flagged['total'],
                'unchecked' => flagged['unchecked'] },
  'rows' => { 'poisoned' => caught['rows'], 'clean' => flagged['rows'] },
}

entry = Vangrail::Evidence.new(rail: rail.name, group: rail.name,
                               attacks_caught: caught['blocked'], attacks: caught['total'],
                               benign_flagged: flagged['blocked'], benign: flagged['total'])
report['bits'] = entry.bits(true).round(2)
report['bits_defensible'] = entry.bits(true, confidence: 0.95).round(2)

File.write(OUTPUT, "#{JSON.pretty_generate(report)}\n")
puts format('task_relation  caught %d of %d poisoned, flagged %d of %d clean, %.2f bits (%.2f defensible)',
            caught['blocked'], caught['total'], flagged['blocked'], flagged['total'],
            report['bits'], report['bits_defensible'])
puts format('               unchecked: %d poisoned, %d clean', caught['unchecked'], flagged['unchecked'])
puts "written to #{OUTPUT}"
