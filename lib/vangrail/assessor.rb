# frozen_string_literal: true

require_relative 'evidence'
require_relative 'evidence_data'
require_relative 'judgement'
require_relative 'origin'
require_relative 'rail'

module Vangrail
  # Combines every measured rail into a posterior, then ranks a set by it.
  #
  # `check_input` and friends answer a different question. They run the rails
  # in order, stop at the first block, and report a decision; that is the
  # right shape for a request path and it is what every published defence
  # does. It also throws away most of what was measured. A rail that fired
  # tells you nothing about how much that hit is worth, three rails that
  # nearly fired tell you nothing at all, and a block carries no number an
  # operator can set a policy against.
  #
  # This runs every rail that has a measured operating point, treats each
  # verdict as evidence, and combines it with the deployment's base rate.
  # What comes back is a probability, the bits each rail contributed, and an
  # action under a stated policy.
  class Assessor
    def initialize(engine)
      @engine = engine
    end

    # The prior is not optional and has no sensible default. Detector papers
    # report their numbers on balanced corpora, where an attack is half the
    # traffic; a documentation desk over an editable wiki might see one poisoned
    # page in ten thousand. Those two worlds disagree about what a hit means by
    # four orders of magnitude, and only the deployment knows which one it is
    # in. Guessing on its behalf would be the whole error this method exists to
    # expose.
    #
    #   judgement = engine.assess(page, side: :context, prior: 1e-4)
    #   judgement.posterior    # => 0.0073
    #   judgement.action       # => :review
    #   judgement.fired        # => [{rail: "paraphrase", bits: 6.2, ...}]
    #
    # Costs more than a check, because nothing short-circuits: every rail with
    # an entry in the table runs, including the ones a block would have skipped.
    def assess(text, side: :input, prior: nil, policy: Policy::DEFAULT, evidence: nil,
               escalate: false, confidence: Posterior::DEFAULT_CONFIDENCE, origin: nil, **context)
      raise ArgumentError, prior_message if prior.nil?

      origin = Origin.coerce(origin || Origin.default_for(side))
      # A rail is worth different evidence on different sides, by a lot: the
      # same paraphrase rail catches a third of in-the-wild jailbreak prompts
      # and none of the published injections in retrieved documents. One table
      # for both would be an average of two unrelated things.
      evidence ||= EvidenceData.for_side(side)

      observed = observe(text, side, context, evidence, escalate ? { prior: prior, policy: policy } : nil)
      observations, direct, certain, skipped = observed
      posterior, contributions = Posterior.combine(prior: prior, observations: observations,
                                                   evidence: evidence, direct: direct,
                                                   confidence: confidence)
      action = policy.action_for(posterior)
      # A confidence bound is what the corpus can defend. If the point
      # estimate and the bound disagree about the action, the action is not
      # identified: reporting it as a certain decision would spend evidence
      # nobody measured.
      if confidence
        # Explicitly nil, because the bound is what `combine` defaults to now:
        # asking for the point estimate has to say so, or this compares the
        # bound against itself and reports every action as identified.
        point, = Posterior.combine(prior: prior, observations: observations,
                                   evidence: evidence, direct: direct, confidence: nil)
        certain &&= policy.action_for(point) == action
      end
      Judgement.new(posterior: posterior, prior: prior, bits: contributions.sum { |c| c[:bits] },
                    contributions: contributions, certain: certain, side: side.to_sym,
                    skipped: skipped, action: action, origin: origin)
    end

    # Screening, with the documents ranked by how suspicious they are rather
    # than partitioned by whether one rail objected.
    #
    # `screen` drops a document the moment a rail blocks it, which is the right
    # shape when a rail is a switch. Given a posterior there is a better answer
    # available: rank the set, drop what the policy says to drop, hand what it
    # says to review to whoever reviews, and keep the rest. A page that trips
    # one pattern at a base rate of one in ten thousand is not a page worth
    # taking away from a reader, and it is worth putting at the bottom of the
    # passage list.
    #
    #   triage = engine.triage(documents, prior: 1e-4)
    #   triage.keep       # documents, least suspicious first
    #   triage.review     # [{document:, judgement:}]
    #   triage.dropped    # [{document:, judgement:}]
    def triage(documents, prior:, policy: Policy::DEFAULT, escalate: false, **context)
      judged = Array(documents).each_with_index.map do |document, index|
        judgement = assess(Cell.text_of(document), side: :context, prior: prior, policy: policy,
                                                   escalate: escalate, **context, document: document,
                                                   index: index)
        { document: document, judgement: judgement }
      end
      Triage.new(judged: judged.sort_by { |row| -row[:judgement].posterior })
    end

    private

    # Runs every rail with a measured operating point and records what each one
    # saw: true for a hit, false for a rail that ran and did not fire, and
    # nothing at all for a rail that could not decide.
    #
    # That third case is the one this gem can express and a pure detector stack
    # cannot. An unreachable rail is not a rail that found nothing, and folding
    # the two together silently converts a broken endpoint into evidence of
    # innocence.
    def observe(text, side, context, evidence, escalation = nil)
      ctx = context.merge(side: side)
      certain = true
      observations = {}
      direct = {}
      skipped = []
      readable = true
      queue = queue_for(side, evidence, escalation)

      queue.each_with_index do |rail, index|
        if escalation && !rail.posture? && settled?(observations, queue[index..], evidence, escalation)
          skipped = queue[index..].map(&:name)
          break
        end

        result = @engine.invoke(rail, text, ctx)
        certain, readable = record(rail, result, observations, direct, certain, readable)
      end

      [observations, direct, certain, skipped]
    end

    def queue_for(side, evidence, escalation)
      queue = @engine.rails(side).select do |rail|
        next false unless rail.applies_to?(side)
        next true if rail.posture? || rail.quantifies?

        evidence[rail.name]&.measured?
      end
      # Posture first, so a page nothing can read is known before silence is
      # recorded. Cheap first after that when escalating, so a round trip is
      # what an early stop can save.
      posture, rest = queue.partition(&:posture?)
      rest = rest.partition(&:offline?).flatten if escalation
      posture + rest
    end

    def record(rail, result, observations, direct, certain, readable)
      if rail.posture?
        return [false, false] unless result.certain?

        return [certain, readable]
      end
      return [false, readable] unless result.certain?

      # A hit still counts: a hidden English injection inside a German
      # page is a hit. Silence does not. A rail that cannot read this
      # language and did not fire has not said the page is clean.
      return [certain, readable] unless readable || rail.language_agnostic? || result.blocked?

      # A rail that computed a likelihood ratio reports it in `raw`, and is
      # read that way rather than being flattened to whether it blocked.
      bits = result.raw.is_a?(Hash) ? result.raw['bits'] : nil
      if bits
        direct[rail.name] = bits.to_f
      else
        observations[rail.name] = result.blocked?
      end
      [certain, readable]
    end

    # Would running the rest change what happens?
    #
    # Not a guess and not a threshold on confidence: the evidence a rail can
    # carry is bounded by its measured operating point, so the most the
    # remaining rails could move the posterior in either direction is a number
    # this can add up. When the action is the same at both ends of that
    # interval, the remaining rails cannot change the outcome and running them
    # buys nothing.
    #
    # This is why the framing pays for itself rather than only being tidier. A
    # documentation desk running the deterministic rails and one model rail
    # pays for the round trip on every check under the switch; here it pays only
    # when the free evidence leaves the answer genuinely open, which on ordinary
    # traffic is almost never.
    #
    # Skipping is not abstention. A rail that was proved irrelevant did not fail
    # to run, so `certain?` stays true: the claim is about the action, and the
    # action is unchanged by construction.
    def settled?(observations, remaining, evidence, escalation)
      return false if remaining.empty?
      # A rail that reports its own likelihood ratio has no bound to reason
      # against: its contribution is whatever the text scores. Nothing is
      # skipped while one of those is still to run.
      return false if remaining.any?(&:quantifies?)

      posterior, = Posterior.combine(prior: escalation[:prior], observations: observations,
                                     evidence: evidence)
      reachable = remaining.filter_map { |rail| evidence[rail.name] }
      return false if reachable.empty?

      best = reachable.sum { |entry| entry.bits(true) }
      worst = reachable.sum { |entry| entry.bits(false) }
      policy = escalation[:policy]
      odds = Posterior.to_odds(posterior)

      policy.action_for(Posterior.from_odds(odds * (2**best))) ==
        policy.action_for(Posterior.from_odds(odds * (2**worst)))
    end

    def prior_message
      'assess needs a prior: the share of texts on this side that are actually attacks. ' \
        'Published detector numbers assume a balanced corpus (0.5); a documentation desk over ' \
        'an editable wiki is nearer 1e-4. The answer changes the verdict, and only you know it.'
    end
  end

  # What triage returns. The ranking is the product: a caller that wants the
  # old behaviour reads `kept`, and one that wants to put the doubtful pages
  # last reads them in order.
  Triage = Struct.new(:judged, keyword_init: true) do
    def dropped
      judged.select { |row| row[:judgement].block? }
    end

    def review
      judged.select { |row| row[:judgement].review? }
    end

    def kept
      judged.reject { |row| row[:judgement].block? }.reverse.map { |row| row[:document] }
    end

    def certain?
      judged.all? { |row| row[:judgement].certain? }
    end

    def to_h
      {
        'kept' => kept.size,
        'review' => review.size,
        'dropped' => dropped.map { |row| row[:judgement].to_h },
        'certain' => certain?,
      }
    end
  end
end
