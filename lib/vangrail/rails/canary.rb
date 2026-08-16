# frozen_string_literal: true

require 'securerandom'
require_relative '../rail'

module Vangrail
  module Rails
    # A marker in the prompt that must never appear anywhere else.
    #
    # Every other rail that cares about the system prompt is guessing: it reads
    # the question for a shape that looks like an extraction attempt, or reads
    # the answer for something that looks like an instruction. This one does
    # not have to guess. The application puts a random string in the prompt, and
    # if that string ever comes back out, the prompt came out with it.
    #
    #   canary = Vangrail::Rails::Canary.generate
    #   prompt = "#{canary}\n#{system_prompt}"
    #   engine = Vangrail::Engine.new(output: [Vangrail::Rails::Canary.new(tokens: canary)])
    #
    # It is exact rather than clever, and that is the whole value: no false
    # positives are possible on a random 16-character token, so it can block
    # outright where a heuristic could only warn.
    #
    # It runs on the input side too. A question containing the canary means the
    # reader already has the prompt from somewhere, which is worth knowing even
    # though it is too late to prevent.
    #
    # What it cannot see is a paraphrase. A model asked to summarise its
    # instructions rather than repeat them leaks the content and not the token,
    # and this rail passes. It is one exact check, not a disclosure defence, and
    # the policy rails still have to do their job.
    class Canary < Rail
      LENGTH = 16

      def self.generate(length: LENGTH)
        "canary-#{SecureRandom.alphanumeric(length)}"
      end

      attr_reader :tokens

      def initialize(tokens:, name: 'canary', sides: %i[input output])
        super(name: name, sides: sides)
        @tokens = Array(tokens).map(&:to_s).reject(&:empty?)
        raise ArgumentError, 'a canary rail needs at least one token' if @tokens.empty?
      end

      def language_agnostic?
        true
      end

      def cache_key(text, _context)
        text
      end

      def decide(text, context)
        body = text.to_s
        # Formatting is not concealment, but a model that writes the token with
        # a line break or a backtick in it has still leaked it, so the
        # comparison ignores anything that is not part of the token itself.
        flat = body.gsub(/[^A-Za-z0-9-]/, '')
        found = tokens.select { |t| body.include?(t) || flat.include?(t.gsub(/[^A-Za-z0-9-]/, '')) }
        return pass if found.empty?

        block(categories: ['canary'], reason: reason_for(context[:side]))
      end

      private

      def reason_for(side)
        return 'the question contains a prompt canary, so the prompt has already leaked' if side == :input

        'the answer contains the prompt canary'
      end
    end
  end
end
