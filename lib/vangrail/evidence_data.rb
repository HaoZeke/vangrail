# frozen_string_literal: true

require_relative 'evidence'

module Vangrail
  # What each rail is worth as evidence, measured on the shipped corpora.
  #
  # GENERATED FILE. Do not edit by hand; rerun script/measure_evidence.rb when
  # a rail changes or a corpus grows. The arithmetic that reads this table
  # lives in evidence.rb, which is hand-written and survives regeneration.
  #
  # Measured over 270 attack texts and 48 benign ones, every rail against the
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
  # 0.60:
  #
    #   alignment                similarity               +0.49
    #   injected_instructions    paraphrase               +0.33
    #   paraphrase               alignment                +0.31
    #   jailbreak                similarity               +0.30
    #   injected_instructions    jailbreak                +0.30
    #   paraphrase               similarity               +0.24
    #   injected_instructions    many_shot                +0.22
    #   injected_instructions    hidden                   +0.21
    #   jailbreak                alignment                +0.19
    #   paraphrase               hidden                   +0.18
    #   jailbreak                paraphrase               +0.11
    #   injected_instructions    similarity               +0.11
    #   jailbreak                many_shot                +0.07
    #   injected_instructions    alignment                +0.07
    #   alignment                many_shot                +0.07
    #   similarity               many_shot                +0.07
    #   paraphrase               many_shot                +0.06
    #   jailbreak                hidden                   +0.03
    #   many_shot                hidden                   -0.04
    #   alignment                hidden                   -0.06
    #   similarity               hidden                   -0.07
    #   many_shot                obfuscation              -0.07
    #   jailbreak                obfuscation              -0.11
    #   obfuscation              hidden                   -0.15
    #   alignment                obfuscation              -0.16
    #   similarity               obfuscation              -0.16
    #   injected_instructions    obfuscation              -0.30
    #   paraphrase               obfuscation              -0.47
  module EvidenceData
    ENTRIES = [
        Evidence.new(rail: "injected_instructions", group: "injected_instructions",
                     attacks_caught: 90, attacks: 270,
                     benign_flagged: 0, benign: 48),
        Evidence.new(rail: "jailbreak", group: "jailbreak",
                     attacks_caught: 16, attacks: 270,
                     benign_flagged: 0, benign: 48),
        Evidence.new(rail: "paraphrase", group: "paraphrase",
                     attacks_caught: 203, attacks: 270,
                     benign_flagged: 0, benign: 48),
        Evidence.new(rail: "alignment", group: "alignment",
                     attacks_caught: 47, attacks: 270,
                     benign_flagged: 0, benign: 48),
        Evidence.new(rail: "similarity", group: "similarity",
                     attacks_caught: 48, attacks: 270,
                     benign_flagged: 0, benign: 48),
        Evidence.new(rail: "many_shot", group: "many_shot",
                     attacks_caught: 6, attacks: 270,
                     benign_flagged: 0, benign: 48),
        Evidence.new(rail: "obfuscation", group: "obfuscation",
                     attacks_caught: 60, attacks: 270,
                     benign_flagged: 0, benign: 48),
        Evidence.new(rail: "hidden", group: "hidden",
                     attacks_caught: 27, attacks: 270,
                     benign_flagged: 0, benign: 48)
    ].freeze

    TABLE = ENTRIES.to_h { |entry| [entry.rail, entry] }.freeze
  end
end
