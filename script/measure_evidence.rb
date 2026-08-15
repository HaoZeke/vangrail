# frozen_string_literal: true

# Regenerates lib/vangrail/evidence_data.rb by running every deterministic rail
# over the same corpora.
#
#   ruby script/measure_evidence.rb
#
# The table this writes is what turns a set of yes-or-no rails into evidence
# that can be added up. Each entry is one rail's detection rate and false-alarm
# rate, and the only reason those numbers can be combined at all is that every
# rail here was measured against the same texts. A detection rate from one
# paper's corpus and a false-alarm rate from another's do not belong in the same
# arithmetic, which is most of why the published defences are compared rather
# than combined.
#
# The corpora are the ones the offline suite already scores rails against, in
# both languages: attacks spliced into documentation prose at five positions,
# rewordings, edited copies of published wordings, and the benign sets carrying
# every near miss the rules were narrowed against.
#
# It also measures which rails agree with each other, because that is the
# assumption everything downstream would otherwise get wrong. Rails that fire on
# the same texts are not independent witnesses, and adding their evidence is how
# a combination rule talks itself into certainty. Pairs above the threshold are
# grouped, and a group speaks once.

$LOAD_PATH.unshift(File.expand_path('../lib', __dir__))
$LOAD_PATH.unshift(File.expand_path('../test', __dir__))
require 'vangrail'
require 'test_injection_corpus'
require 'test_paraphrase'
require 'test_multilingual'
require 'test_similarity'

OUT = File.expand_path('../lib/vangrail/evidence_data.rb', __dir__)

# Correlation above this and two rails are treated as one witness. Set from the
# measured matrix rather than from taste: the pairs that share a mechanism sit
# far above it, and the pairs that merely overlap sit far below.
GROUP_AT = 0.6

# The threat mix is a modelling choice, not a fact, and it decides every number
# downstream. A rail measured on a corpus containing none of the attacks it was
# built for has not been measured at all: run without the encoded and pasted
# families below, the decoding rail scores zero catches and the arithmetic
# concludes that a hit from it is evidence of innocence.
#
# So every family a shipped rail targets is represented here, and a deployment
# whose real mix differs should say so by regenerating this table rather than by
# reading these numbers as universal.
def attack_corpus
  corpus = TestInjectionCorpus.new('x')
  injections = corpus.corpus.map { |c| c[:text] }
  encoded = corpus.encoded_corpus.map { |c| c[:text] }
  hidden = TestInjectionCorpus::INJECTIONS.map do |injection|
    "#{TestInjectionCorpus::BENIGN.first}\n<!-- #{injection} -->\n<p>See the reference pages.</p>"
  end
  pasted = TestInjectionCorpus::INJECTIONS.first(6).map do |injection|
    turns = (1..6).map { |i| "user: question #{i}\nassistant: of course, here it is." }.join("\n")
    "#{turns}\nuser: #{injection}"
  end
  reworded = TestParaphrase.new('x').corpus.map { |c| c[:text] }
  dutch = TestMultilingual.new('x').corpus.map { |c| c[:text] }
  edited = TestSimilarity::EDITED.map { |text| "#{TestParaphrase::BENIGN.first}\n\n#{text}" }
  (injections + encoded + hidden + pasted + reworded + dutch + edited).uniq
end

def benign_corpus
  (TestInjectionCorpus::BENIGN + TestParaphrase::BENIGN + TestMultilingual::BENIGN).uniq
end

# Only the rails that answer "is this an attack". A redaction rail is not in
# here: it says a token was present, which is a fact about the text rather than
# evidence about an attacker, and folding it in would let an ordinary answer
# quoting a config file push a judgement towards blocked.
def rails
  deterministic = [Vangrail::Rails::InjectedInstructions.new,
                   Vangrail::Rails::Jailbreak.new(sides: [:context]),
                   Vangrail::Rails::Paraphrase.new(sides: [:context]),
                   Vangrail::Rails::Similarity.new(sides: [:context]),
                   Vangrail::Rails::ManyShot.new(sides: [:context])]
  deterministic + [Vangrail::Rails::Obfuscation.new(rails: deterministic, sides: [:context]),
                   Vangrail::Rails::Hidden.new(rails: deterministic)]
end

def hits(rail, texts)
  texts.map { |text| rail.call(text, side: :context).blocked? }
end

attacks = attack_corpus
benign = benign_corpus
warn "attack corpus: #{attacks.size}, benign corpus: #{benign.size}"

measured = rails.to_h do |rail|
  [rail.name, { attack: hits(rail, attacks), benign: hits(rail, benign) }]
end

# Phi coefficient over the whole corpus: the correlation of two binary
# variables, which is what two rails' verdicts are.
def phi(left, right)
  n11 = left.zip(right).count { |a, b| a && b }
  n10 = left.zip(right).count { |a, b| a && !b }
  n01 = left.zip(right).count { |a, b| !a && b }
  n00 = left.zip(right).count { |a, b| !a && !b }
  denominator = Math.sqrt((n11 + n10) * (n01 + n00) * (n11 + n01) * (n10 + n00))
  return 0.0 if denominator.zero?

  ((n11 * n00) - (n10 * n01)) / denominator
end

names = measured.keys
vectors = names.to_h { |name| [name, measured[name][:attack] + measured[name][:benign]] }

correlations = {}
names.combination(2).each do |a, b|
  correlations[[a, b]] = phi(vectors[a], vectors[b])
end

# Union-find over the pairs above the threshold, so a chain of correlated rails
# lands in one group rather than in overlapping pairs.
parent = names.to_h { |name| [name, name] }
find = lambda do |name|
  name = parent[name] while parent[name] != name
  name
end
correlations.each do |(a, b), value|
  next if value < GROUP_AT

  ra = find.call(a)
  rb = find.call(b)
  parent[ra] = rb unless ra == rb
end
groups = names.to_h { |name| [name, find.call(name)] }

rows = names.map do |name|
  {
    rail: name,
    attacks_caught: measured[name][:attack].count(true),
    attacks: attacks.size,
    benign_flagged: measured[name][:benign].count(true),
    benign: benign.size,
    group: groups[name],
  }
end

matrix = correlations.sort_by { |_, value| -value }.map do |(a, b), value|
  format('    #   %-24s %-24s %+.2f%s', a, b, value, value >= GROUP_AT ? '  grouped' : '')
end

body = rows.map do |row|
  "        Evidence.new(rail: #{row[:rail].inspect}, group: #{row[:group].inspect}," \
    "\n                     attacks_caught: #{row[:attacks_caught]}, attacks: #{row[:attacks]}," \
    "\n                     benign_flagged: #{row[:benign_flagged]}, benign: #{row[:benign]})"
end

File.write(OUT, <<~RUBY)
  # frozen_string_literal: true

  require_relative 'evidence'

  module Vangrail
    # What each rail is worth as evidence, measured on the shipped corpora.
    #
    # GENERATED FILE. Do not edit by hand; rerun script/measure_evidence.rb when
    # a rail changes or a corpus grows. The arithmetic that reads this table
    # lives in evidence.rb, which is hand-written and survives regeneration.
    #
    # Measured over #{attacks.size} attack texts and #{benign.size} benign ones, every rail against the
    # same set. The attack side is injections spliced into documentation prose at
    # five positions, rewordings of the same asks, the Dutch corpus, and edited
    # copies of published wordings. The benign side is ordinary documentation in
    # both languages, including every near miss the rules were narrowed against.
    #
    # These are not universal constants and must not be read as any. They are
    # this corpus, whose attack half was written by the same hand as the rails,
    # and they will be optimistic about attacks that hand did not think of. What
    # the table is for is the ratio between rails, and that ratio is honest:
    # every number in it came from the same texts.
    #
    # Correlation between rails, phi over the combined corpus, grouped above
    # #{format('%.2f', GROUP_AT)}:
    #
  #{matrix.join("\n")}
    module EvidenceData
      ENTRIES = [
  #{body.join(",\n")}
      ].freeze

      TABLE = ENTRIES.to_h { |entry| [entry.rail, entry] }.freeze
    end
  end
RUBY

puts "wrote #{OUT}"
PRIORS = [0.5, 1e-2, 1e-4].freeze

puts '  rail                     caught/flagged      fired   at 95%  CID 0.5 CID 1e-4'
rows.each do |row|
  entry = Vangrail::Evidence.new(**row)
  puts format('  %-24s %6d/%-3d %3d/%-3d %+8.1f %+8.1f %8.3f %8.3f',
              row[:rail], row[:attacks_caught], row[:attacks], row[:benign_flagged], row[:benign],
              entry.bits(true), entry.bits(true, confidence: 0.95),
              entry.capability(prior: PRIORS.first), entry.capability(prior: PRIORS.last))
end
puts
puts 'fired    : bits a hit is worth, point estimate'
puts 'at 95%   : bits this corpus can defend at 95% confidence, which is the number to trust'
puts 'CID      : share of the uncertainty about "is this an attack" the rail removes, per base rate'
