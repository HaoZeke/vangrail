# frozen_string_literal: true

require_relative '../rail'

module Vangrail
  module Rails
    # Reads a retrieved document for instructions aimed at the model.
    #
    # This is the rail most stacks are missing. The input rail checks what the
    # user typed and the output rail checks what the model wrote, and neither
    # ever looks at the wiki page, search result, or file that the application
    # pasted into the prompt in between. That page is the part an attacker can
    # usually edit without touching the application at all.
    #
    # Deterministic on purpose. The text is written by whoever wants it to be
    # believed, so a model asked to judge it is reading an argument composed to
    # persuade it. A pattern cannot be argued with, costs microseconds, and
    # keeps working when the endpoint does not.
    #
    # Patterns match shapes that have no honest reason to appear in
    # documentation: a role header mid-page, an override of "the above", a claim
    # about what the assistant must now do. Ordinary prose that happens to
    # discuss instructions is not a hit, because a handbook says "follow the
    # instructions above" constantly.
    class InjectedInstructions < Rail
      PATTERNS = {
        # A chat role header inside a document: nothing in prose needs one.
        # The Dutch role names sit beside the English ones because a role
        # header is a shape rather than a sentence, and a page that writes
        # "assistent:" mid-paragraph is doing what "assistant:" does.
        'role_header' => /^\s{0,3}(?:###\s*)?(?:system|systeem|assistant|assistent|user|gebruiker)\s*:\s*\S/i,
        # An override aimed at whatever came before it in the prompt.
        'override_above' => /\b(?:ignore|disregard|forget|override)\b[^.\n]{0,40}\b
                             (?:above|previous|prior|earlier|preceding|system\s+prompt|instructions?)\b/xi,
        # A document telling the assistant what it is now.
        'role_assignment' => /\byou\s+(?:are|must\s+now\s+act|will\s+now\s+act)\s+(?:now\s+)?
                              (?:a|an|the)?\s*(?:assistant|ai|model|chatbot|dan)\b/xi,
        # An instruction to conceal something *from the reader*, which is what
        # separates an injection from ordinary advice.
        #
        # Three narrowings, each paid for by a false positive found in the
        # corpus. "In your response" and "when answering" alone flag a handbook
        # talking to a human ("in your response to the service desk, include the
        # job id"). A bare "never mention" flags security advice ("never mention
        # a password in a ticket"). So the concealment has to be tied either to
        # the user or to the act of answering, in whichever order it is written.
        'answer_shaping' => /
          \b(?:do\s+not|don't|never)\s+(?:mention|reveal|disclose|tell|say|admit)\b[^.\n]{0,40}?
            \b(?:to\s+(?:the\s+|this\s+)?user|to\s+them|in\s+your\s+(?:answer|response|reply)|
               when\s+you\s+(?:answer|respond))\b
          |
          \b(?:in\s+your\s+(?:answer|response|reply)|when\s+(?:you\s+)?(?:answer|answering|respond))\b[^.\n]{0,40}?
            \b(?:do\s+not|don't|never)\s+(?:mention|reveal|disclose|tell|say|admit)\b
          |
          \bwithout\s+(?:mentioning|telling)\s+(?:the\s+|this\s+)?user\b
        /xi,
        # Exfiltration shapes: a document asking for the prompt or the key.
        'exfiltration' => /\b(?:reveal|print|repeat|output|send|post)\b[^.\n]{0,40}\b
                           (?:system\s+prompt|api[_\s-]?key|token|credentials?|conversation)\b/xi,
        # Hidden text: a marker for content meant for the model and not the
        # reader. HTML comments in a rendered page are the common carrier.
        'hidden_directive' => /<!--[^>]*\b(?:ignore|instruction|assistant|system|prompt|
                                             negeer|instructie|assistent|systeem)\b[^>]*-->/imx
      }.freeze

      attr_reader :patterns

      def initialize(patterns: PATTERNS, name: 'injected_instructions', sides: [:context])
        super(name: name, sides: sides)
        @patterns = patterns
      end

      def offline?
        true
      end

      def cache_key(text, _context)
        text
      end

      def call(text, _context)
        body = text.to_s
        hits = patterns.select { |_label, pattern| pattern.match?(body) }.keys
        return pass if hits.empty?

        block(categories: hits, reason: "instructions found in retrieved text: #{hits.join(', ')}")
      end
    end
  end
end
