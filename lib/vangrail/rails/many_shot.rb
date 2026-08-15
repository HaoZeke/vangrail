# frozen_string_literal: true

require_relative '../rail'

module Vangrail
  module Rails
    # Catches a fake conversation pasted into a real one.
    #
    # Two attacks share this shape. The first writes the model's own chat
    # template into the text: the control tokens a server uses to separate
    # system from user from assistant are ordinary characters by the time they
    # reach a prompt, so a message containing them can close the user turn and
    # open a system one. The second needs no special tokens at all and works by
    # volume, filling the context with dozens of invented exchanges in which an
    # assistant answers everything it is asked, until the pattern of the
    # conversation outweighs the instructions at the top. The published
    # measurement of that one is a success rate rising with the number of
    # examples, which is why counting is a reasonable defence.
    #
    # Two responses, because the right one differs:
    #
    #   template tokens   stripped, and reported as a rewrite
    #   many-shot volume  blocked
    #
    # Stripping rather than blocking the tokens is deliberate. On a desk that
    # documents machine-learning software, "how do I use <|im_start|> in my
    # template?" is a real question, and refusing it teaches the reader that
    # the guardrail is the obstacle. Removed from the text, the token cannot
    # restructure a prompt, and the question survives.
    #
    # The volume threshold is on invented turns rather than on length. A long
    # question is not an attack, and four alternations of a dialogue that never
    # happened is not a long question.
    class ManyShot < Rail
      # Chat template control tokens across the common families. These are not
      # patterns that need judgement: text arriving from a reader has no honest
      # reason to carry a delimiter the serving layer inserts.
      TEMPLATE_TOKENS = /
        <\|(?:im_start|im_end|start_header_id|end_header_id|eot_id|begin_of_text|
             system|user|assistant|endoftext|end_of_turn|start_of_turn)\|>
        |\[\/?INST\]|<<\/?SYS>>|<\|channel\|>|<\|message\|>
      /xi

      # A role header at the start of a line, which is how a pasted transcript
      # is written when it is not using template tokens.
      TURN = /^\s{0,3}(?:###\s*)?(?:system|user|human|assistant|ai|bot|q|a)\s*:\s*\S/i

      attr_reader :max_turns, :placeholder

      def initialize(max_turns: 4, placeholder: '', name: 'many_shot', sides: %i[input context])
        super(name: name, sides: sides)
        @max_turns = max_turns
        @placeholder = placeholder
      end

      def offline?
        true
      end

      def cache_key(text, _context)
        text
      end

      def call(text, _context)
        body = text.to_s
        turns = body.scan(TURN).size
        if turns > max_turns
          return block(categories: ['many_shot'],
                       reason: "#{turns} conversation turns in one message")
        end

        stripped = body.gsub(TEMPLATE_TOKENS, placeholder)
        return pass if stripped == body

        modify(stripped, categories: ['template_tokens'],
                         reason: 'removed chat template control tokens')
      end
    end
  end
end
