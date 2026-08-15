# frozen_string_literal: true

require_relative '../chat'
require_relative '../parsers'
require_relative '../policies'
require_relative '../rail'

module Vangrail
  module Rails
    # Judges where a conversation is going, not what its newest message says.
    #
    # Rails::Escalation is the deterministic half of the multi-turn problem and
    # is honest about its limit: it sees nothing until a refusal happens, and
    # the published multi-turn methods are built precisely so that no turn ever
    # triggers one. Each message is a reasonable follow-up to the answer before
    # it, the assistant's own output is the foothold for the next step, and the
    # escalation exists only in the sequence.
    #
    # Reading a sequence for intent is what a model can do and a regexp cannot,
    # so this rail sends the transcript to the judge model and asks about the
    # direction rather than the content.
    #
    # It costs a round trip per turn, which is why it is opt-in and why
    # `every` exists: judging one turn in three is a defensible trade for a
    # documentation desk, since a staged escalation takes several turns by
    # construction and cannot complete inside the gap.
    #
    #   Rails::Trajectory.new(provider: provider, min_turns: 4, every: 2)
    #
    # Below `min_turns` it passes and says it is certain, which is a real
    # judgement rather than a dodge: a two-message conversation has no
    # trajectory, and the single-turn rails have already read both messages.
    # On a skipped turn it passes with `certain?` false, because that turn was
    # not judged and an application reading the flag deserves to know which
    # kind of pass it has.
    class Trajectory < Rail
      DEFAULT_MIN_TURNS = 4

      attr_reader :model, :chat, :policy, :min_turns, :every, :window

      def initialize(provider: nil, model: nil, chat: nil, policy: nil,
                     min_turns: DEFAULT_MIN_TURNS, every: 1, window: 12,
                     name: 'trajectory', max_tokens: 256, **chat_options)
        super(name: name, sides: [:input])
        @model = model || provider&.model(:judge)
        @policy = policy || Policies.trajectory_policy
        @min_turns = min_turns
        @every = [every.to_i, 1].max
        @window = window
        @chat = chat || begin
          raise ArgumentError, 'a trajectory rail needs a provider or a chat client' unless provider

          Chat.new(model: @model, base_url: provider.base_url, api_key: provider.api_key,
                   max_tokens: max_tokens, **chat_options)
        end
      end

      # Never memoizable: the same message means different things depending on
      # what it follows.
      def cache_key(_text, _context)
        nil
      end

      def call(text, context)
        turns = Array(context[:history]).last(window)
        return pass if turns.size < min_turns

        return unchecked("not judged this turn (every #{every})") unless due?(turns)

        judge(text, turns)
      end

      private

      # Counted over the dialogue rather than a call counter, so two engines
      # sharing a conversation skip the same turns and a retry does not shift
      # the schedule.
      def due?(turns)
        (turns.size % every).zero?
      end

      def judge(text, turns)
        answer = chat.ask([
                            { 'role' => 'system', 'content' => policy },
                            { 'role' => 'user', 'content' => Policies.trajectory_prompt(turns, text) },
                          ])
        parsed = Parsers.policy(answer.text)
        unless parsed[:decided]
          return Result.new(status: :passed, rail: name, certain: false, model: model,
                            latency_ms: answer.latency_ms, raw: answer.raw,
                            reason: "unparsed judge response: #{parsed[:reason]}")
        end

        return pass(model: model, latency_ms: answer.latency_ms, raw: answer.raw) unless parsed[:violated]

        block(reason: parsed[:reason], categories: parsed[:categories], model: model,
              latency_ms: answer.latency_ms, raw: answer.raw)
      end
    end
  end
end
