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
  # Context: 125 published BIPIA injections spliced into installed
  # documentation, plus 120 attacks from this repository's own corpus, against
  # 18258 real documents from the same machine. Two attack families on
  # purpose: BIPIA's off-task instructions, which no deterministic rail here
  # catches, and the override-and-disclosure family the rails were built for,
  # which the shipped corpus covers and which nobody else's benchmark does.
  # The ratio is 125:120 and a deployment whose traffic is not that mix
  # should reweight it and rerun the script.
  #
  # Input: 1405 in-the-wild jailbreak prompts against the
  # 13735 ordinary prompts collected beside them.
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
        Evidence.new(rail: "injected_instructions", group: "injected_instructions",
                     attacks_caught: 58, attacks: 245,
                     benign_flagged: 48, benign: 18258),
        Evidence.new(rail: "jailbreak", group: "jailbreak",
                     attacks_caught: 10, attacks: 245,
                     benign_flagged: 20, benign: 18258),
        Evidence.new(rail: "paraphrase", group: "paraphrase",
                     attacks_caught: 61, attacks: 245,
                     benign_flagged: 235, benign: 18258),
        Evidence.new(rail: "similarity", group: "similarity",
                     attacks_caught: 12, attacks: 245,
                     benign_flagged: 0, benign: 18258),
        Evidence.new(rail: "many_shot", group: "many_shot",
                     attacks_caught: 0, attacks: 245,
                     benign_flagged: 2, benign: 18258),
        Evidence.new(rail: "obfuscation", group: "obfuscation",
                     attacks_caught: 60, attacks: 245,
                     benign_flagged: 59, benign: 18258),
        Evidence.new(rail: "hidden", group: "hidden",
                     attacks_caught: 5, attacks: 245,
                     benign_flagged: 0, benign: 18258),
        Evidence.new(rail: "bayes", group: "bayes",
                     attacks_caught: 100, attacks: 245,
                     benign_flagged: 1617, benign: 18258)
    ].freeze

    INPUT = [
        Evidence.new(rail: "injection_patterns", group: "injection_patterns",
                     attacks_caught: 35, attacks: 1405,
                     benign_flagged: 730, benign: 13735),
        Evidence.new(rail: "jailbreak", group: "jailbreak",
                     attacks_caught: 190, attacks: 1405,
                     benign_flagged: 134, benign: 13735),
        Evidence.new(rail: "paraphrase", group: "paraphrase",
                     attacks_caught: 492, attacks: 1405,
                     benign_flagged: 1666, benign: 13735),
        Evidence.new(rail: "similarity", group: "similarity",
                     attacks_caught: 127, attacks: 1405,
                     benign_flagged: 857, benign: 13735),
        Evidence.new(rail: "many_shot", group: "many_shot",
                     attacks_caught: 10, attacks: 1405,
                     benign_flagged: 34, benign: 13735),
        Evidence.new(rail: "obfuscation", group: "obfuscation",
                     attacks_caught: 253, attacks: 1405,
                     benign_flagged: 439, benign: 13735),
        Evidence.new(rail: "bayes", group: "bayes",
                     attacks_caught: 340, attacks: 1405,
                     benign_flagged: 1715, benign: 13735)
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
