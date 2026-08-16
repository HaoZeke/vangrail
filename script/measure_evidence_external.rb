# frozen_string_literal: true

# Rewrites lib/vangrail/evidence_data.rb from corpora this repository did not
# write.
#
#   ruby script/fetch_external.rb
#   ruby script/measure_false_alarms.rb 20000
#   ruby script/measure_external.rb
#   ruby script/measure_evidence_external.rb
#
# The table this replaces was measured on 270 attacks and 48 benign texts, all
# written here. It said paraphrase was worth six bits. Measured against
# published attacks and eighteen thousand real documents, the same rail is worth
# something else entirely, and two of the numbers change sign.
#
# One benign source per side, and an attack population whose composition is
# stated. The context side is BIPIA's published injections plus this
# repository's own, against installed documentation; the input side is
# in-the-wild jailbreak prompts against the ordinary prompts collected beside
# them. Mixing two attack families is fine and declared; mixing a detection rate
# from one corpus with a false-alarm rate from another is the error this exists
# to stop repeating, and the benign side never mixes.
$LOAD_PATH.unshift(File.expand_path('../lib', __dir__))
require 'json'
require 'vangrail'
require_relative 'handbook_corpus'

EXTERNAL = ARGV[0] || File.expand_path('../tmp/external_results.json', __dir__)
FALSE_ALARMS = ARGV[1] || File.expand_path('../tmp/false_alarms.json', __dir__)
OUT = File.expand_path('../lib/vangrail/evidence_data.rb', __dir__)

external = JSON.parse(File.read(EXTERNAL))
alarms = JSON.parse(File.read(FALSE_ALARMS))

# The context attack population is deliberately two families, and saying so is
# the whole point.
#
# BIPIA's injections are off-task instructions: they carry no override, no
# disclosure, and no concealment, and every deterministic rail here catches
# exactly none of them. A table built on them alone reports that a rail firing
# on a document is evidence against an attack, which is true of that corpus and
# false as a description of the rails.
#
# The corpus this repository wrote covers the other family, the one the rails
# were built for, and scores them at sixty of sixty because it was written out
# of the same idea of an attack. Neither number is the answer.
#
# So the population is both, mixed at whatever ratio the two corpora happen to
# have, and the ratio is stated here rather than buried: a deployment whose
# traffic is mostly one family should reweight it and rerun.

def local_attacks
  HandbookCorpus.local_attacks
end

CONTEXT_RAILS = (Vangrail::Builder.deterministic(:context).reject { |rail| rail.name == 'language' } +
                 [Vangrail::Rails::Bayes.new(sides: [:context])]).freeze

own = local_attacks
own_caught = CONTEXT_RAILS.to_h do |rail|
  [rail.name, own.count { |text| rail.call(text, side: :context).blocked? }]
end
warn "own-corpus attacks: #{own.size}"

# The context side's benign measurement is the big one: 18k real documents
# rather than the 600 pages the external run scored, so it is read from the
# dedicated run.
context_benign_n = alarms['documents']
context = external['context']['rails'].to_h do |name, row|
  flagged = alarms['counts'][name] || row['flagged']
  [name, { caught: row['caught'] + own_caught.fetch(name, 0),
           attacks: external['context']['attacks'] + own.size,
           flagged: flagged, benign: context_benign_n }]
end

input = external['input']['rails'].to_h do |name, row|
  [name, { caught: row['caught'], attacks: external['input']['attacks'],
           flagged: row['flagged'], benign: external['input']['benign'] }]
end

def entries_for(table)
  table.map do |name, row|
    "        Evidence.new(rail: #{name.inspect}, group: #{name.inspect}," \
      "\n                     attacks_caught: #{row[:caught]}, attacks: #{row[:attacks]}," \
      "\n                     benign_flagged: #{row[:flagged]}, benign: #{row[:benign]})"
  end
end

def summarise(label, table)
  puts label
  puts format('  %-24s %8s %10s %8s %10s', 'rail', 'caught', 'flagged', 'bits', 'at 95%')
  table.each do |name, row|
    entry = Vangrail::Evidence.new(rail: name, attacks_caught: row[:caught], attacks: row[:attacks],
                                   benign_flagged: row[:flagged], benign: row[:benign])
    puts format('  %-24s %4d/%-4d %5d/%-6d %+8.1f %+10.1f', name, row[:caught], row[:attacks],
                row[:flagged], row[:benign], entry.bits(true), entry.bits(true, confidence: 0.95))
  end
  puts
end

summarise('context', context)
summarise('input', input)

File.write(OUT, <<~RUBY)
  # frozen_string_literal: true

  require_relative 'evidence'

  module Vangrail
    # What each rail is worth as evidence, measured on corpora written by other
    # people.
    #
    # GENERATED FILE. Do not edit by hand; rerun script/measure_evidence_external.rb.
    # The arithmetic that reads this table lives in evidence.rb, which is
    # hand-written and survives regeneration.
    #
    # One benign source per side; the attack population is stated.
    #
    # Context: #{external['context']['attacks']} published BIPIA injections spliced into installed
    # documentation, plus #{own.size} attacks from this repository's own corpus, against
    # #{context_benign_n} real documents from the same machine. Two attack families on
    # purpose: BIPIA's off-task instructions, which no deterministic rail here
    # catches, and the override-and-disclosure family the rails were built for,
    # which the shipped corpus covers and which nobody else's benchmark does.
    # The ratio is #{external['context']['attacks']}:#{own.size} and a deployment whose traffic is not that mix
    # should reweight it and rerun the script.
    #
    # Input: #{external['input']['attacks']} in-the-wild jailbreak prompts against the
    # #{external['input']['benign']} ordinary prompts collected beside them.
    #
    # Read the context numbers before trusting anything built on them. Every
    # deterministic rail catches none of the published injections, because BIPIA's
    # attacks are off-task instructions carrying no override, no disclosure, and
    # no concealment, and those three are all these rails know how to find. A
    # rail that fires on a document under this measurement is reporting a false
    # alarm more often than an attack, and the sign of its evidence says so.
    #
    # That is a statement about a threat model, not a verdict on the rails: the
    # corpus this repository wrote scores them at 60 of 60, because it was
    # written out of the same idea of an attack. Both numbers are real and
    # neither is the answer on its own.
    module EvidenceData
      CONTEXT = [
  #{entries_for(context).join(",\n")}
      ].freeze

      INPUT = [
  #{entries_for(input).join(",\n")}
      ].freeze

      ENTRIES = (CONTEXT + INPUT).freeze

      BY_SIDE = {
        context: CONTEXT.to_h { |entry| [entry.rail, entry] }.freeze,
        input: INPUT.to_h { |entry| [entry.rail, entry] }.freeze
      }.freeze

      # A rail's operating point depends on which side it runs on, by a lot: the
      # same rail is worth different evidence reading a retrieved document and
      # reading a question. The default is the input table because that is the
      # side with a detection measurement worth having.
      TABLE = BY_SIDE[:input]

      def self.for_side(side)
        BY_SIDE[side.to_sym] || TABLE
      end
    end
  end
RUBY

puts "wrote #{OUT}"
