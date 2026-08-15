# frozen_string_literal: true

require_relative 'engine'
require_relative 'result'
require_relative 'session'

module Vangrail
  # A dialogue, so rails can see more than the turn in front of them.
  #
  # Every rail so far reads one string. That is enough for the attacks that fit
  # in one string, and it is exactly wrong for the ones built out of turns that
  # are individually unremarkable: ask something harmless, ask for more detail
  # about the part of the answer that helps, keep going until the thing you
  # wanted is on screen. No single message in that sequence looks like an
  # attack, because none of them is one.
  #
  # So this holds the turns and threads them into the rail context as
  # `:history`, which the rail protocol has always carried and nothing has ever
  # filled in. A rail that ignores history behaves exactly as before.
  #
  #   convo = Vangrail::Conversation.new(engine)
  #   verdict = convo.ask(question)
  #   convo.answer(text) if verdict.allowed?
  #
  # What it also does is remember the verdicts. A refusal is the most
  # informative event in a dialogue: the next message is either an ordinary
  # follow-up or the same request rewritten, and telling those apart is
  # impossible without knowing a refusal happened.
  #
  # Pass `prior:` and the same turns also feed a Session. Escalation sees
  # the refusals; the posterior sees the sequence that never refused.
  # They are different questions and they share one history.
  #
  #   convo = Vangrail::Conversation.new(engine, prior: 1e-3)
  #   convo.ask(question)
  #   convo.session.posterior
  class Conversation
    Turn = Struct.new(:role, :text, :result, keyword_init: true) do
      def blocked?
        result&.blocked? || false
      end

      def user?
        role == :user
      end

      def to_h
        { 'role' => role.to_s, 'text' => text, 'result' => result&.to_h }.compact
      end
    end

    # How many turns of history the rails see. A dialogue that has been running
    # for an hour is mostly irrelevant to whether this message is a retry, and
    # an unbounded window makes the cost of a check grow with the session.
    DEFAULT_WINDOW = 12

    attr_reader :engine, :turns, :window, :session

    def initialize(engine, window: DEFAULT_WINDOW, session: nil, prior: nil, **context)
      raise ArgumentError, 'pass session: or prior:, not both' if session && prior

      @engine = engine
      @window = window
      @base_context = context
      @turns = []
      @session = session || (prior && Session.new(engine: engine, prior: prior))
    end

    # Checks a question and records it, whatever the verdict. A blocked turn
    # stays in the history: it is the part the next check needs most.
    def ask(text, **context)
      seen = history
      result = engine.check_input(text, history: seen, **@base_context, **context)
      @turns << Turn.new(role: :user, text: text.to_s, result: result)
      @session&.observe(text, side: :input, history: seen)
      result
    end

    def answer(text, **context)
      result = engine.check_output(text, history: history, **@base_context, **context)
      @turns << Turn.new(role: :assistant, text: content_of(result, text), result: result)
      result
    end

    # Screens retrieved documents with the dialogue in view, so a context rail
    # can see which question they were fetched for.
    def screen(documents, **context)
      engine.screen(documents, history: history, **@base_context, **context)
    end

    # The window the rails read: role and text, no Result objects, because a
    # rail should not be reasoning about another rail's verdict text.
    def history
      turns.last(window).map { |t| { role: t.role, text: t.text, blocked: t.blocked? } }
    end

    def blocked_turns
      turns.select { |t| t.user? && t.blocked? }
    end

    def blocked?
      !blocked_turns.empty?
    end

    def last_user_turn
      turns.reverse.detect(&:user?)
    end

    def to_h
      {
        'turns' => turns.map(&:to_h),
        'blocked' => blocked_turns.size,
        'session' => session&.to_h,
      }.compact
    end

    private

    def content_of(result, fallback)
      result.respond_to?(:content_or) ? result.content_or(fallback.to_s) : fallback.to_s
    end
  end
end
