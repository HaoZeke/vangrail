# frozen_string_literal: true

require_relative 'engine'
require_relative 'errors'
require_relative 'origin'
require_relative 'profile'
require_relative 'result'
require_relative 'session'
require_relative 'spotlight'
require_relative 'tools'

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
  # Pass `prior:` and the same turns also feed a Session. One engine walk
  # per turn: assess when a session is present, otherwise check_input.
  # Escalation is not an assess term, so a retry after a refusal is
  # caught on the path without a session.
  #
  # After ask and screen both tracks have turns. Name the channel;
  # `block?` is true if either would block.
  #
  #   convo = Vangrail::Conversation.new(engine, prior: 1e-3)
  #   convo.ask(question)
  #   convo.screen(documents)
  #   convo.session.posterior(:attack)
  #   convo.session.posterior(:contamination)
  #   convo.session.block?
  class Conversation
    Turn = Struct.new(:role, :text, :result, :origin, keyword_init: true) do
      def blocked?
        result&.blocked? || false
      end

      def user?
        role == :user
      end

      def to_h
        { 'role' => role.to_s, 'text' => text, 'origin' => origin&.to_s,
          'result' => result&.to_h }.compact
      end
    end

    # How many turns of history the rails see. A dialogue that has been running
    # for an hour is mostly irrelevant to whether this message is a retry, and
    # an unbounded window makes the cost of a check grow with the session.
    DEFAULT_WINDOW = 12

    attr_reader :engine, :turns, :window, :session, :admission, :retrieved, :capabilities,
                :tools, :invocations, :profile

    def initialize(engine, window: DEFAULT_WINDOW, session: nil, prior: nil,
                   allow: {}, admission: nil, capabilities: nil, tools: nil,
                   profile: nil, deny: [], hooks: {}, **context)
      raise ArgumentError, 'pass session: or prior:, not both' if session && prior

      @engine = engine
      @window = window
      @base_context = context
      @turns = []
      @retrieved = []
      @invocations = []
      @intended = []
      @locked = false
      @pinned = false
      @hooks = hooks
      @tools = tools || Tools.new
      @profile = Profile.resolve(profile, allow: allow, deny: deny)
      @capabilities = capabilities.nil? ? nil : Array(capabilities).map(&:to_sym).freeze
      @session = session || (prior && Session.new(engine: engine, prior: prior))
      @admission = admission || Admission.new(allow: @profile.allow)
    end

    # Checks a question and records it, whatever the verdict. A blocked turn
    # stays in the history: it is the part the next check needs most.
    #
    # One engine walk: assess when a session is present, check_input
    # otherwise. Assess does not run Escalation. That object is folded
    # onto the Turn and the Session.
    def ask(text, **context)
      @pinned = true
      seen = history
      ctx = { history: seen, **@base_context, **context }
      result = if @session
                 judgement = engine.assess(text, side: :input, origin: Origin.user,
                                           **session_assess, **ctx)
                 @session.fold(judgement)
                 result_from(judgement)
               else
                 engine.check_input(text, **ctx)
               end
      @turns << Turn.new(role: :user, text: text.to_s, result: result, origin: Origin.user)
      result
    end

    def answer(text, **context)
      result = engine.check_output(text, history: history, **@base_context, **context)
      turn = Turn.new(role: :assistant, text: content_of(result, text), result: result,
                      origin: Origin.tool)
      @turns << turn
      @session&.fold(result, origin: turn.origin, side: :output)
      result
    end

    # Screens retrieved documents with the dialogue in view, so a context rail
    # can see which question they were fetched for. A session, if any, records
    # every judged page on the contamination track, rejected ones included:
    # instruction-shaped data is poisoned retrieval, not a user attack.
    # Retrieved cells stay the survivors.
    def screen(documents, **context)
      seen = history
      result = engine.screen(documents, history: seen, **@base_context, **context)
      @retrieved = result.cells
      @locked = true
      @intended.freeze
      Array(documents).each do |document|
        @session&.observe(Cell.text_of(document), side: :context, origin: :data, history: seen)
      end
      result
    end

    # Names the tools this question is allowed to use, before any
    # retrieved page is seen. That is the privileged planner: the plan
    # is fixed from the user turn. After `screen`, the plan is locked.
    # A page that names a new tool cannot add it.
    def intend(*names)
      raise Error, 'ask before intending a tool' unless last_user_turn
      raise PrivilegeError, 'the plan is locked: data has already been seen' if locked?

      names.each do |name|
        name = name.to_sym
        raise ArgumentError, "unknown tool #{name}" unless tools.key?(name)

        @intended << name unless @intended.include?(name)
      end
      intended
    end

    def intended
      @intended.dup.freeze
    end

    def locked?
      @locked
    end

    # Whether this dialogue may exercise a capability. The request is the
    # last user turn, carrying the conversation's capability set. A bare
    # argument string is data. Nothing is admitted before anyone has asked,
    # and a name that is not in the allowlist is not admitted either.
    def admit?(capability, arguments: nil)
      turn = last_user_turn
      return false unless turn

      args = case arguments
             when nil then nil
             when Cell then arguments
             else Cell.data(arguments)
             end
      admission.permit?(capability, request: Cell.user(turn.text, capabilities: capabilities),
                                    arguments: args)
    end

    # The only assembly this object will produce. The question is the last
    # user turn; the passages are the cells `screen` kept. A caller who
    # pastes retrieved text into `system:` or `question:` has to do it
    # without this method, which is the point.
    def messages(system:, mode: :delimit, mark: Spotlight::DEFAULT_MARK)
      turn = last_user_turn
      raise Error, 'ask before assembling a prompt' unless turn

      Spotlight.messages(system: system, question: Cell.user(turn.text),
                         passages: retrieved, mode: mode, mark: mark)
    end

    # Runs a named tool only if Admission grants it. A refused call is a
    # blocked turn, not a handler that almost ran. The return value of a
    # granted handler is wrapped as a tool-origin cell.
    def invoke(name, arguments: nil)
      name = name.to_sym
      raise ArgumentError, "unknown tool #{name}" unless tools.key?(name)

      if profile.denied?(name)
        result = Result.blocked(rail: 'deny', reason: "capability #{name} is denied by profile")
        record_invocation(name, arguments, result, nil)
        return result
      end

      if profile.readonly? && !tools.readonly?(name)
        result = Result.blocked(rail: 'profile', reason: "profile #{profile.name} is read-only")
        record_invocation(name, arguments, result, nil)
        return result
      end

      hook = run_pre_invoke(name, arguments)
      return hook if hook

      unless @intended.include?(name)
        result = Result.blocked(rail: 'plan', reason: "capability #{name} was not intended")
        record_invocation(name, arguments, result, nil)
        return result
      end

      unless admit?(name, arguments: arguments)
        result = Result.blocked(rail: 'admission', reason: "capability #{name} refused")
        record_invocation(name, arguments, result, nil)
        return result
      end

      value = tools.call(name, arguments, self)
      cell = value.is_a?(Cell) ? value : Cell.tool(value)
      result = Result.passed(rail: name.to_s)
      record_invocation(name, arguments, result, cell)
      result
    end

    def invoked?(name)
      invocations.any? { |row| row[:name] == name.to_sym && row[:result].allowed? }
    end

    # A span pulled out of retrieved data. The result is still data.
    def extract(pattern)
      retrieved.filter_map do |cell|
        match = cell.value[pattern]
        Cell.data(match) if match
      end
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

    def child_env(source = ENV)
      profile.strip_secrets? ? Profile.strip_secrets(source) : source.to_h
    end

    def to_h
      {
        'turns' => turns.map(&:to_h),
        'blocked' => blocked_turns.size,
        'invoked' => invocations.select { |row| row[:result].allowed? }.map { |row| row[:name].to_s },
        'intended' => @intended.map(&:to_s),
        'locked' => locked?,
        'profile' => profile.name.to_s,
        'session' => session&.to_h,
      }.compact
    end

    private

    def run_pre_invoke(name, arguments)
      hook = @hooks[:pre_invoke]
      return nil unless hook

      verdict = hook.call(name, arguments, self)
      if verdict.is_a?(Result)
        record_invocation(name, arguments, verdict, nil)
        return verdict
      end
      return nil if verdict

      result = Result.blocked(rail: 'hook', reason: "pre_invoke refused #{name}")
      record_invocation(name, arguments, result, nil)
      result
    end

    def record_invocation(name, arguments, result, cell)
      @invocations << { name: name, arguments: arguments, result: result, cell: cell }
      turn = Turn.new(role: :tool, text: name.to_s, result: result, origin: Origin.tool)
      @turns << turn
      @session&.fold(result, origin: turn.origin, side: :output)
    end

    def session_assess
      options = { prior: @session.prior, policy: @session.policy }
      options[:evidence] = @session.evidence if @session.evidence
      options
    end

    def result_from(judgement)
      if judgement.block? || judgement.fired.any?
        rail = judgement.fired.dig(0, :rail) || judgement.side.to_s
        return Result.blocked(rail: rail, certain: judgement.certain?)
      end

      Result.passed(rail: judgement.side.to_s, certain: judgement.certain?)
    end

    def content_of(result, fallback)
      result.respond_to?(:content_or) ? result.content_or(fallback.to_s) : fallback.to_s
    end

    def text_of(document)
      return document.to_s unless document.is_a?(Hash)

      (document['text'] || document[:text]).to_s
    end
  end
end
