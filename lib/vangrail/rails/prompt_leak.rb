# frozen_string_literal: true

require_relative '../nlp'
require_relative '../rail'

module Vangrail
  module Rails
    # Catches the answer that is reproducing the system prompt.
    #
    # Rails::Canary catches the exact token and nothing else, which its own
    # documentation says: a model asked to summarise its instructions rather
    # than repeat them leaks the content and not the marker. That is the
    # published shape of the attack, and it is the row the coverage page marks
    # as verbatim-only.
    #
    # The application already has the text that must not come back out. So
    # nothing here has to guess what a system prompt looks like: the answer's
    # sentences are compared against the protected text's sentences by n-gram
    # containment, and a sentence made largely of the prompt's n-grams is the
    # prompt, however it was introduced.
    #
    # Sentence against sentence, for the reason Rails::Similarity gives:
    # containment saturates with length, so a short answer compared against a
    # whole prompt scores high on nothing at all.
    #
    # Redacted rather than refused. An answer that quotes one line of its
    # instructions is usually a useful answer with one bad sentence in it, and
    # blocking throws away the help to prevent the leak while rewriting keeps
    # both. What comes back is the answer with those sentences replaced.
    class PromptLeak < Rail
      PLACEHOLDER = '[redacted: system prompt]'

      # Two thresholds, because reproducing a rule and applying one are not the
      # same act and score alike.
      #
      # "I cannot speculate about quotas; ask the service desk" restates a line
      # of the prompt and is exactly what the prompt is for. "My instructions
      # say I cannot speculate about quotas" restates the same line and hands
      # the reader the instruction. What separates them is not how much text
      # they share; it is that the second one says whose words they are.
      #
      # So: a sentence that reproduces the protected text closely is a leak
      # whatever frame it carries, and a sentence that reproduces it loosely is
      # a leak only when it announces that it is quoting the assistant's own
      # instructions. Measured in test/test_prompt_leak.rb: ordinary answers
      # top out at 0.27, and quotes start at 0.45.
      THRESHOLD = 0.7
      FRAMED_THRESHOLD = 0.4

      # A sentence naming the assistant's own instructions. Written here rather
      # than in the shared lexicon on purpose: first-person possessives belong
      # to an answer, and adding them to NLP's `self` concept would have the
      # input side read "print my configuration" as an extraction attempt.
      FRAME = /
        \b(?:my|these|those|the|its|your)\s+
          (?:instructions?|rules?|guidelines?|system\s+(?:prompt|message)|prompt|directives?)\b
        |
        \bI\s+(?:was|am|have\s+been)\s+(?:told|instructed|configured|programmed|asked)\b
        |
        \b(?:system|developer)\s+(?:prompt|message)\s+(?:says|states|reads|is)\b
        |
        \b(?:mijn|deze|die|jouw|uw)\s+
          (?:instructies?|regels?|richtlijnen?|systeemprompt|voorschriften?)\b
        |
        \bik\s+(?:ben|werd|was)\s+(?:geïnstrueerd|geïnstrueerd|verteld|geconfigureerd|geprogrammeerd|gevraagd)\b
        |
        \bsysteemprompt\s+(?:zegt|staat|luidt|is)\b
      /xi

      # Shorter than this, a sentence is not evidence. "You may not." is inside
      # the n-gram set of almost any prompt, and redacting it would cost a
      # reader an answer to prevent nothing.
      FLOOR = 40

      attr_reader :threshold, :framed_threshold, :placeholder

      def initialize(protected_text:, threshold: THRESHOLD, framed_threshold: FRAMED_THRESHOLD,
                     floor: FLOOR, placeholder: PLACEHOLDER, name: 'prompt_leak', sides: [:output])
        super(name: name, sides: sides)
        @threshold = threshold
        @framed_threshold = framed_threshold
        @floor = floor
        @placeholder = placeholder
        @protected = protect(protected_text)
        raise ArgumentError, 'a prompt_leak rail needs protected text' if @protected.empty?
      end

      def cache_key(text, _context)
        "#{threshold}\n#{text}"
      end

      def decide(text, _context)
        body = text.to_s
        leaked = sentences(body).select { |sentence| leak?(sentence) }
        return pass if leaked.empty?

        redacted = leaked.reduce(body) { |acc, sentence| acc.sub(sentence, placeholder) }
        modify(redacted, categories: ['system_prompt'],
                         reason: "redacted #{leaked.size} sentence(s) reproducing the protected text")
      end

      # How much of the protected text a sentence reproduces, for a caller that
      # wants the number rather than the verdict.
      def score(sentence)
        shingles = NLP.shingles(sentence)
        @protected.map { |candidate| NLP.containment(shingles, candidate) }.max || 0.0
      end

      private

      def sentences(text)
        NLP.clauses(text).select { |clause| clause.length >= @floor }
      end

      def leak?(sentence)
        found = score(sentence)
        return true if found >= threshold

        found >= framed_threshold && sentence.match?(FRAME)
      end

      # The protected text as one shingle set per sentence. Sentences below the
      # floor are dropped from it as well: a prompt's one-word line is not
      # something an answer can leak.
      def protect(text)
        Array(text).flat_map { |part| NLP.clauses(part) }
                   .select { |clause| clause.length >= @floor }
                   .map { |clause| NLP.shingles(clause) }
      end
    end
  end
end
