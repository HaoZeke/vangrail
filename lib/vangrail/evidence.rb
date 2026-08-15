# frozen_string_literal: true

module Vangrail
  # One rail's measured operating point, read as evidence rather than as a
  # verdict.
  #
  # Every rail in this gem answers a yes-or-no question, and the engine combines
  # those answers by taking the first "yes". That is what the published defences
  # do too, and it throws away almost everything the rails know. It cannot say
  # how much a hit is worth, cannot add up three near misses, and cannot tell an
  # operator what a block actually means about the text.
  #
  # What a hit is worth is a ratio, and it is measurable: how much likelier this
  # rail is to fire on an attack than on ordinary documentation. That number,
  # the likelihood ratio, is all a rail needs to contribute to a shared
  # judgement, and it is exactly what the corpora in this repository already
  # measure. Every entry here comes from running a rail over the same attack and
  # benign sets as every other rail, which is what makes the numbers comparable
  # in the first place: a detection rate measured on one paper's corpus and a
  # false-positive rate measured on another's cannot be combined at all.
  #
  # Rates are smoothed with the Jeffreys prior, (hits + 1/2) / (n + 1), for a
  # reason that is not decoration. A rail that caught 60 of 60 has an unsmoothed
  # detection rate of exactly 1, an unsmoothed likelihood ratio of infinity, and
  # would single-handedly decide every judgement it appears in on the strength
  # of a sixty-item corpus. Smoothing keeps the evidence finite and proportional
  # to how much was actually measured.
  Evidence = Struct.new(:rail, :attacks_caught, :attacks, :benign_flagged, :benign, :group,
                        keyword_init: true) do
    # Probability the rail fires given the text is an attack.
    def detection
      (attacks_caught + 0.5) / (attacks + 1.0)
    end

    # Probability it fires given the text is ordinary.
    def false_alarm
      (benign_flagged + 0.5) / (benign + 1.0)
    end

    # How much likelier a hit is on an attack than on ordinary text.
    def ratio_fired
      detection / false_alarm
    end

    # And how much likelier silence is on ordinary text than on an attack. This
    # is the half that OR-combination cannot express at all: a sensitive rail
    # staying quiet is evidence too, and it points the other way.
    def ratio_silent
      (1 - detection) / (1 - false_alarm)
    end

    # Evidence in bits, positive towards attack. Bits rather than nats because
    # an operator has to read these: one bit is a doubling of the odds, and
    # "this rail is worth four bits" is a sentence somebody can act on.
    def bits(fired)
      Math.log2(fired ? ratio_fired : ratio_silent)
    end

    # A rail that never fired on either corpus has measured nothing, whatever
    # its detection rate looks like after smoothing.
    def measured?
      attacks.positive? && benign.positive?
    end

    def to_h
      {
        'rail' => rail, 'group' => group,
        'attacks_caught' => attacks_caught, 'attacks' => attacks,
        'benign_flagged' => benign_flagged, 'benign' => benign,
        'detection' => detection.round(4), 'false_alarm' => false_alarm.round(4),
        'bits_if_fired' => bits(true).round(2), 'bits_if_silent' => bits(false).round(2)
      }
    end
  end

  # Combines rail evidence into a posterior probability that the text is an
  # attack.
  #
  # The arithmetic is one line: odds after = odds before times every likelihood
  # ratio. In bits it is addition, which is why the contributions of individual
  # rails can be printed and read.
  #
  # Three things make this more than a formality, and all three are things the
  # published defences leave on the floor.
  #
  # The prior is the deployment's, and it dominates. Detector papers evaluate on
  # balanced corpora, where half the traffic is an attack; a documentation desk
  # sees maybe one poisoned page in ten thousand. At that base rate a rail with
  # a one percent false-alarm rate is wrong far more often than it is right when
  # it fires, and no amount of detection rate fixes it. That is not a criticism
  # of the rails: it is the arithmetic every operator inherits and almost none
  # is shown.
  #
  # Abstention is evidence of nothing, which is different from evidence against.
  # A rail that was off, unreachable, or undecided contributes no term at all,
  # and this gem is unusual in knowing which rails those were: `certain?` is
  # exactly that fact, and here it finally has arithmetic to feed.
  #
  # Correlated rails do not each get a vote. Three rails that fire on the same
  # sentence for the same reason are one observation reported three times, and
  # summing them is how naive Bayes talks itself into certainty. Rails measured
  # to agree are grouped, and a group contributes once.
  module Posterior
    module_function

    # Combines and returns [posterior, contributions].
    #
    # `observations` maps a rail name to true (fired), false (ran and did not
    # fire), or nil (did not run). The nils are the point.
    def combine(prior:, observations:, evidence: EvidenceData::TABLE)
      raise ArgumentError, 'prior must be strictly between 0 and 1' unless prior.positive? && prior < 1

      contributions = weigh(observations, evidence)
      total = contributions.sum { |c| c[:bits] }
      [from_odds(to_odds(prior) * (2**total)), contributions]
    end

    # One term per group rather than one per rail.
    #
    # Within a group, the firing rail with the most evidence speaks for the
    # group; if none fired, the most sensitive member's silence speaks for it.
    # Both rules pick the single most informative member, which is the
    # conservative reading of a set of observations that are not independent.
    def weigh(observations, evidence)
      seen = observations.filter_map do |rail, fired|
        next if fired.nil?

        entry = evidence[rail.to_s]
        next unless entry&.measured?

        { rail: rail.to_s, group: entry.group || rail.to_s, fired: fired, entry: entry }
      end

      seen.group_by { |o| o[:group] }.map { |group, members| speak_for(group, members) }
    end

    def speak_for(group, members)
      fired = members.select { |m| m[:fired] }
      chosen = if fired.empty?
                 members.max_by { |m| m[:entry].detection }
               else
                 fired.max_by { |m| m[:entry].bits(true) }
               end

      {
        group: group,
        rail: chosen[:rail],
        fired: chosen[:fired],
        bits: chosen[:entry].bits(chosen[:fired]),
        spoke_for: members.map { |m| m[:rail] }
      }
    end

    # How many bits it takes to get from a base rate to a target confidence.
    #
    # This is the number the whole design turns on, and it is worth being able
    # to compute rather than assert. Reaching an even-money posterior from one
    # attack in ten thousand takes about 13.3 bits, and no rail in this gem is
    # worth half that, which is a statement about what a single detector can
    # honestly justify rather than about these particular rails.
    def required_bits(prior:, target: 0.5)
      Math.log2(to_odds(target) / to_odds(prior))
    end

    # The false-alarm rate a single rail would need to carry a block on its own.
    #
    # Rearranged from the same identity: at base rate `prior`, one rail with
    # detection `detection` reaches `target` only if it almost never fires on
    # ordinary text. The answers come out in the region of one in ten thousand,
    # which is below what any hand-built benign corpus can demonstrate: showing
    # a rate that low needs tens of thousands of clean documents on which the
    # rail stayed silent.
    #
    # That is the practical case for combining rails rather than trusting one,
    # and it is an argument about evidence rather than about taste.
    def false_alarm_needed(prior:, detection: 0.75, target: 0.5)
      detection / (to_odds(target) / to_odds(prior))
    end

    def to_odds(probability)
      probability / (1 - probability)
    end

    def from_odds(odds)
      return 1.0 if odds.infinite?

      odds / (1 + odds)
    end
  end
end
