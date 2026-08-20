# frozen_string_literal: true

require_relative 'engine'
require_relative 'evidence'
require_relative 'judgement'
require_relative 'origin'

module Vangrail
  # The posterior over a session rather than over a message.
  #
  # Every check in this gem, and every detector in the published work, judges
  # one string and forgets it. That is the wrong shape for the attack family
  # that actually gets through a desk: ask something harmless, ask for more
  # detail about the part of the answer that helped, keep going. No message in
  # that sequence is an attack, which is why per-message detection is blind to
  # it, and Rails::Escalation only catches the crude version where a refusal is
  # followed by a retry.
  #
  # Read as evidence, the sequence is the obvious case. Three turns that each
  # move the odds by two bits have moved them by six, and a reader whose every
  # question is unremarkable but slightly odd looks exactly like what they are:
  # unlikely, three times over. Nothing about that needs a new detector. It
  # needs the arithmetic to carry across turns, which is one multiplication.
  #
  # Two things keep it from becoming a session that eventually blocks everyone.
  #
  # Evidence decays. Between turns the excess over the prior is multiplied by
  # `decay`, so a session's posture reflects recent behaviour rather than
  # everything since login. This is the standard forgetting factor of sequential
  # inference with drift, and the drift here is real: the person asking is
  # allowed to change what they are doing, and a reader who asked one odd
  # question an hour ago is not a suspect.
  #
  # Ordinary turns push back. A clean turn contributes the silence of every rail
  # that ran, which is negative evidence, so a session recovers rather than only
  # ratcheting. A reader who trips one rail and then asks twenty normal
  # questions ends where they started.
  #
  #   session = Vangrail::Session.new(engine: engine, prior: 1e-3)
  #   session.observe(question)          # => Judgement for the turn
  #   session.posterior                  # => the session's, not the turn's
  #   session.action                     # => :allow, :review, :block
  #
  # After a retrieved page or an answer, both tracks have turns. Unnamed
  # `posterior` and `action` raise then. Name the channel:
  #
  #   session.posterior(:attack)
  #   session.posterior(:contamination)
  #   session.block?                     # true if either track would block
  #
  # The per-turn judgement is still returned, because both numbers are real and
  # they answer different questions. "Is this message an attack" is what a
  # request path routes on. "Is this session an attack" is what a desk wants
  # before it decides whether a reader is probing it.
  class Session
    # How much of the accumulated excess survives to the next turn. At 0.6, two
    # bits of suspicion are worth about one and a quarter after one ordinary
    # turn and a third of a bit after four, so a single odd question fades in a
    # handful of turns while a pattern of them does not.
    DEFAULT_DECAY = 0.6

    # One rank's running total. Attack and contamination each have one;
    # they decay and accumulate on their own clock and they do not add.
    class Track
      attr_accessor :log_odds, :cusum
      attr_reader :turns

      def initialize(log_odds)
        @log_odds = log_odds
        @cusum = 0.0
        @turns = []
      end

      def posterior
        Posterior.from_odds(2**log_odds)
      end

      def bits(prior)
        log_odds - Math.log2(Posterior.to_odds(prior))
      end
    end

    attr_reader :engine, :prior, :decay, :policy, :alpha, :beta, :channel,
                :attack, :contamination, :evidence

    # `alpha` and `beta` are the error rates a sequential test is allowed: how
    # often it may call an ordinary reader an attacker, and how often it may
    # miss one. Given those two numbers the thresholds are not a choice, which
    # is the whole appeal of the sequential test.
    def initialize(engine:, prior:, decay: DEFAULT_DECAY, policy: Policy::DEFAULT,
                   alpha: 0.01, beta: 0.05, evidence: nil)
      raise ArgumentError, 'prior must be strictly between 0 and 1' unless prior.positive? && prior < 1
      raise ArgumentError, 'decay must be in (0, 1]' unless decay.positive? && decay <= 1
      raise ArgumentError, 'alpha and beta must be in (0, 1)' unless [alpha, beta].all? { |v| v.positive? && v < 1 }

      @engine = engine
      @prior = prior
      @decay = decay
      @policy = policy
      @alpha = alpha
      @beta = beta
      base = Math.log2(Posterior.to_odds(prior))
      @attack = Track.new(base)
      @contamination = Track.new(base)
      @channel = nil
      # An operating point given outright, for a caller measuring the
      # arithmetic rather than the shipped corpus.
      @evidence = evidence
    end

    # Judges one turn and folds it into the session.
    #
    # The turn's own judgement is computed against the session's prior rather
    # than against the session's current posterior, deliberately. Feeding the
    # running posterior back in as the prior would compound the same evidence
    # every turn and reach certainty on a reader who did nothing new; the
    # accumulation belongs in the session's state, not in each turn's premise.
    #
    # `origin` defaults from the side: a question is a user span, a retrieved
    # page is data. Privileged origin updates the attack track. Untrusted
    # origin updates contamination. The two numbers never add: a poisoned
    # wiki page cannot accuse a reader, and a reader cannot contaminate a
    # document they did not write.
    def observe(text, side: :input, origin: nil, **context)
      origin = Origin.coerce(origin || Origin.default_for(side))
      options = evidence ? { evidence: evidence } : {}
      judgement = engine.assess(text, side: side, prior: prior, policy: policy,
                                      origin: origin, **options, **context)
      fold(judgement)
      judgement
    end

    # Folds a judgement, or a Result from a walk that already ran.
    # `origin` and `side` name the span when the event is a Result; a
    # Judgement already carries both.
    def fold(event, origin: nil, side: nil)
      judgement = coerce(event, origin: origin, side: side)
      origin = judgement.origin || Origin.default_for(judgement.side || :input)
      @channel ||= origin.channel
      apply(track_for(origin.channel), judgement)
      self
    end

    def log_odds(channel = nil)
      named_track(channel).log_odds
    end

    def turns(channel = nil)
      named_track(channel).turns
    end

    def cusum(channel = nil)
      named_track(channel).cusum
    end

    # Turns that landed on the other rank. They still moved that rank's
    # posterior; they did not move this one.
    def quarantined
      other.turns
    end

    def posterior(channel = nil)
      named_track(channel).posterior
    end

    # How far the session sits from where it started, in bits. The readable
    # summary: zero is an ordinary session, and positive is a reader who keeps
    # doing things that ordinary readers do not.
    def bits(channel = nil)
      named_track(channel).bits(prior)
    end

    def action(channel = nil)
      policy.action_for(posterior(channel))
    end

    # Without a name this is true if either populated track would block.
    # Unnamed posterior and action raise once both tracks have turns.
    def block?(channel = nil)
      return action(channel) == :block if channel

      tracks_for_block.any? { |track| policy.action_for(track.posterior) == :block }
    end

    def review?(channel = nil)
      action(channel) == :review
    end

    def allow?(channel = nil)
      action(channel) == :allow
    end

    # Wald's sequential test over the same accumulated evidence.
    #
    # The posterior answers "how likely is this"; the sequential test answers a
    # question an operator often prefers: "have I seen enough to decide, at
    # error rates I chose in advance". It is the older machinery, it is what the
    # network-detection work uses for exactly this shape of problem, and it
    # costs nothing extra here because the log-likelihood ratio is already being
    # accumulated.
    #
    # Two thresholds, both fixed by alpha and beta rather than by taste:
    # accumulate until the evidence passes log((1 - beta) / alpha) and call it
    # an attack, or falls below log(beta / (1 - alpha)) and call it ordinary.
    # In between, the honest answer is that the session has not said enough yet.
    #
    # Reported beside the posterior rather than instead of it. They answer
    # different questions and disagreeing is informative: a session that the
    # test calls undecided while the policy says review is a session where the
    # cost argument and the error-rate argument point different ways, and
    # somebody should know that.
    def verdict(channel = nil)
      score = bits(channel)
      return :attack if score >= upper_threshold
      return :benign if score <= lower_threshold

      :undecided
    end

    def upper_threshold
      Math.log2((1 - beta) / alpha)
    end

    def lower_threshold
      Math.log2(beta / (1 - alpha))
    end

    # How much more evidence the test needs before it can decide, in bits.
    def bits_to_decide(channel = nil)
      return 0.0 unless verdict(channel) == :undecided

      score = bits(channel)
      [upper_threshold - score, score - lower_threshold].min
    end

    # True when the recent burst of attack-direction evidence has reached
    # the same bar Wald uses for the accumulated total. A change of
    # behaviour, not a lifetime score.
    def shift?(channel = nil)
      cusum(channel) >= upper_threshold
    end

    # False as soon as any turn was judged without every rail reaching a
    # decision, because the session's number inherits every gap in the turns
    # that built it.
    def certain?
      attack.turns.all?(&:certain?) && contamination.turns.all?(&:certain?)
    end

    def to_h
      single = !ambiguous?
      {
        'prior' => prior,
        'posterior' => (posterior.round(6) if single),
        'bits' => (bits.round(2) if single),
        'decay' => decay,
        'turns' => single ? turns.size : attack.turns.size + contamination.turns.size,
        'channel' => channel&.to_s,
        'quarantined' => (quarantined.size unless quarantined.empty?),
        'attack' => track_h(attack),
        'contamination' => track_h(contamination),
        'action' => (action.to_s if single),
        'verdict' => (verdict.to_s if single),
        'cusum' => (cusum.round(2) if single),
        'shift' => (shift? if single),
        'certain' => certain?,
      }.compact
    end

    def to_s
      if ambiguous?
        return format('session attack p=%<attack>.4f contamination p=%<data>.4f',
                      attack: attack.posterior, data: contamination.posterior)
      end

      format('session %<action>s p=%<posterior>.4f over %<turns>d turn(s), %<bits>+.1f bits',
             action: action, posterior: posterior, turns: turns.size, bits: bits)
    end

    private

    def primary
      @channel == :contamination ? @contamination : @attack
    end

    def other
      primary.equal?(@attack) ? @contamination : @attack
    end

    def track_for(name)
      key = name.to_sym
      raise ArgumentError, "unknown channel #{name.inspect}" unless %i[attack contamination].include?(key)

      key == :attack ? @attack : @contamination
    end

    def named_track(channel = nil)
      return track_for(channel) if channel
      raise ArgumentError, 'name the channel: :attack or :contamination' if ambiguous?

      contamination.turns.empty? ? attack : contamination
    end

    def ambiguous?
      !attack.turns.empty? && !contamination.turns.empty?
    end

    def tracks_for_block
      populated = [attack, contamination].reject { |track| track.turns.empty? }
      populated.empty? ? [attack] : populated
    end

    def coerce(event, origin:, side:)
      return event if event.is_a?(Judgement)

      origin = Origin.coerce(origin || Origin.default_for(side || :output))
      side = (side || :output).to_sym
      fired = event.blocked? || event.modified?
      bits = bits_from_result(event, side, fired)
      posterior = Posterior.from_odds(Posterior.to_odds(prior) * (2**bits))
      Judgement.new(posterior: posterior, prior: prior, bits: bits,
                    contributions: [{ rail: event.rail.to_s, bits: bits, fired: fired }],
                    certain: event.certain?, action: policy.action_for(posterior),
                    side: side, origin: origin)
    end

    def bits_from_result(event, side, fired)
      return 0.0 unless event.certain?

      table = evidence || EvidenceData.for_side(side)
      entry = table[event.rail.to_s] if table && event.rail
      # No operating point is zero bits. Unmeasured is not a leak.
      entry&.measured? ? entry.bits(fired) : 0.0
    end

    def apply(track, judgement)
      decay_track(track)
      # Uncertain is not evidence: the same increment updates the odds
      # and the CUSUM. Bits already exclude abstaining rails; a turn
      # that did not finish every rail still does not move the session.
      increment = judgement.certain? ? judgement.bits : 0.0
      track.log_odds += increment
      # Page (1954). Reference value is 0: accumulate only excess toward
      # attack. The threshold is Wald's upper bar, so the error rate is
      # the one the caller already chose.
      track.cusum = [0.0, (track.cusum * decay) + increment].max
      track.turns << judgement
    end

    # Multiply the excess over the prior, not the odds. Decaying the odds
    # themselves would drag a session towards even money from both directions,
    # which would make a long clean session look suspicious.
    def decay_track(track)
      base = Math.log2(Posterior.to_odds(prior))
      track.log_odds = base + ((track.log_odds - base) * decay)
    end

    def track_h(track)
      return nil if track.turns.empty?

      { 'posterior' => track.posterior.round(6), 'bits' => track.bits(prior).round(2),
        'turns' => track.turns.size }
    end
  end
end
