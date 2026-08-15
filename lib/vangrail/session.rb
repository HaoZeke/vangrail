# frozen_string_literal: true

require_relative 'engine'
require_relative 'evidence'
require_relative 'judgement'

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

    attr_reader :engine, :prior, :decay, :policy, :log_odds, :turns

    def initialize(engine:, prior:, decay: DEFAULT_DECAY, policy: Policy::DEFAULT)
      raise ArgumentError, 'prior must be strictly between 0 and 1' unless prior.positive? && prior < 1
      raise ArgumentError, 'decay must be in (0, 1]' unless decay.positive? && decay <= 1

      @engine = engine
      @prior = prior
      @decay = decay
      @policy = policy
      @log_odds = Math.log2(Posterior.to_odds(prior))
      @turns = []
    end

    # Judges one turn and folds it into the session.
    #
    # The turn's own judgement is computed against the session's prior rather
    # than against the session's current posterior, deliberately. Feeding the
    # running posterior back in as the prior would compound the same evidence
    # every turn and reach certainty on a reader who did nothing new; the
    # accumulation belongs in the session's state, not in each turn's premise.
    def observe(text, side: :input, **context)
      judgement = engine.assess(text, side: side, prior: prior, policy: policy, **context)
      fold(judgement)
      judgement
    end

    # Folds a judgement computed elsewhere, for a caller that already ran one.
    def fold(judgement)
      decay_towards_prior
      @log_odds += judgement.bits
      @turns << judgement
      self
    end

    def posterior
      Posterior.from_odds(2**log_odds)
    end

    # How far the session sits from where it started, in bits. The readable
    # summary: zero is an ordinary session, and positive is a reader who keeps
    # doing things that ordinary readers do not.
    def bits
      log_odds - Math.log2(Posterior.to_odds(prior))
    end

    def action
      policy.action_for(posterior)
    end

    def block?
      action == :block
    end

    def review?
      action == :review
    end

    def allow?
      action == :allow
    end

    # False as soon as any turn was judged without every rail reaching a
    # decision, because the session's number inherits every gap in the turns
    # that built it.
    def certain?
      turns.all?(&:certain?)
    end

    def to_h
      {
        'prior' => prior,
        'posterior' => posterior.round(6),
        'bits' => bits.round(2),
        'decay' => decay,
        'turns' => turns.size,
        'action' => action.to_s,
        'certain' => certain?
      }
    end

    def to_s
      format('session %<action>s p=%<posterior>.4f over %<turns>d turn(s), %<bits>+.1f bits',
             action: action, posterior: posterior, turns: turns.size, bits: bits)
    end

    private

    # Multiply the excess over the prior, not the odds. Decaying the odds
    # themselves would drag a session towards even money from both directions,
    # which would make a long clean session look suspicious.
    def decay_towards_prior
      base = Math.log2(Posterior.to_odds(prior))
      @log_odds = base + ((@log_odds - base) * decay)
    end
  end
end
