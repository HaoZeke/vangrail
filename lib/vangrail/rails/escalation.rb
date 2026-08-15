# frozen_string_literal: true

require_relative '../rail'

module Vangrail
  module Rails
    # Watches what happens after a refusal.
    #
    # The multi-turn attacks work because the guardrail forgets. A request is
    # refused, the next message is the same request with the objectionable word
    # removed, and the rail reads it as a fresh question because that is all it
    # has ever been given. Repeat until something gets through. The published
    # multi-turn methods differ in how they choose the rewrite, and they share
    # that one assumption: that turn N+1 is judged without turn N.
    #
    # So this rail judges the sequence rather than the message. It reads
    # `:history` from the context, which a Conversation fills in, and it has
    # exactly two things to say:
    #
    #   retry_after_refusal   the last question was refused, and this one is
    #                         that question again: mostly the same words, or a
    #                         bare reference back to it, or a reframing opener
    #                         ("hypothetically", "just for research") on top of
    #                         it
    #   repeated_refusals     several refusals in a short window, whatever this
    #                         particular message says
    #
    # Both are cheap and neither is clever. A caller with no history configured
    # gets a pass and an honest `certain?` of false, because a rail that reads
    # history and was given none has not checked anything.
    #
    # The limit is worth stating: a genuine crescendo never triggers a refusal
    # at all until the last turn, and this rail sees nothing until one happens.
    # It raises the cost of the cheap version of the attack, where the attacker
    # probes until something lands. Judging a dialogue that has never been
    # refused needs a model reading the trajectory, which is a different rail
    # and a round trip.
    class Escalation < Rail
      # A retry does not have to be a paraphrase. It can be a pointer.
      REFERENCE_BACK = /
        \A[^.?!]{0,60}\b(?:as\s+i\s+(?:said|asked|mentioned)|like\s+i\s+(?:said|asked)|
           (?:the|my)\s+(?:previous|last|earlier)\s+(?:question|request|message)|
           try\s+again|answer\s+(?:it|that|the\s+question)\s+anyway|
           just\s+(?:answer|tell|say)|come\s+on|continue|go\s+on|please\s+continue)\b
      /xi

      # The openers that exist to relabel a refused request as something else.
      REFRAMING = /
        \b(?:hypothetically|in\s+theory|for\s+(?:a\s+)?(?:friend|research|a\s+paper|
           educational\s+purposes|academic\s+purposes)|purely\s+(?:academic|hypothetical)|
           what\s+if\s+i\s+(?:told\s+you|said)|imagine\s+(?:that\s+)?you|
           let\s+me\s+rephrase|to\s+(?:re)?phrase\s+(?:it|that)\s+differently|
           you\s+misunderstood|that\s+is\s+not\s+what\s+i\s+(?:meant|asked))\b
      /xi

      STOP = %w[
        the a an and or but is are was were be been being to of in on at for with
        from by as it its this that these those i you he she they we me my your do
        does did how what why when where can could would should will shall may
        might must not no yes if then than so about into over under please
      ].freeze

      attr_reader :overlap, :window, :tolerance

      # `overlap` is the share of this question's content words that also
      # appeared in the refused one. Three fifths is where the corpus put it: a
      # rewrite keeps the nouns and changes the verb, so it lands near two
      # thirds, while a genuine follow-up on the same subject shares one or two
      # words out of seven. Higher and the measured rewrites walk through;
      # lower and one refusal makes the topic unaskable, which ends the
      # conversation rather than the attack.
      def initialize(overlap: 0.6, window: 6, tolerance: 2, name: 'escalation', sides: [:input])
        super(name: name, sides: sides)
        @overlap = overlap
        @window = window
        @tolerance = tolerance
      end

      def offline?
        true
      end

      # Not memoizable: the same question means different things depending on
      # what came before it, which is the entire premise of the rail.
      def cache_key(_text, _context)
        nil
      end

      def call(text, context)
        history = Array(context[:history])
        return unchecked('no history was provided, so nothing was compared') if history.empty?

        refused = history.select { |t| user?(t) && t[:blocked] }
        return pass if refused.empty?

        recent = history.last(window).count { |t| user?(t) && t[:blocked] }
        if recent > tolerance
          return block(categories: ['repeated_refusals'],
                       reason: "#{recent} refused questions in the last #{window} turns")
        end

        retry_of(text.to_s, refused.last)
      end

      private

      def retry_of(text, last_refusal)
        return pass if last_refusal.nil?

        shape = retry_shape(text, last_refusal[:text].to_s)
        return pass if shape.nil?

        block(categories: ['retry_after_refusal', shape].compact,
              reason: "the previous question was refused and this one is #{describe(shape)}")
      end

      # Ordered by how much it says. A paraphrase is the strongest signal
      # because it needs no interpretation: the same content words in a new
      # sentence, one turn after a refusal.
      def retry_shape(text, previous)
        return 'paraphrase' if similar?(text, previous)
        return 'reframed' if text.match?(REFRAMING) && shares_topic?(text, previous)
        return 'reference_back' if text.match?(REFERENCE_BACK)

        nil
      end

      def describe(shape)
        case shape
        when 'paraphrase' then 'the same question again'
        when 'reframed' then 'the same question with a reframing opener'
        else 'a request to answer it anyway'
        end
      end

      def similar?(text, previous)
        now = content_words(text)
        before = content_words(previous)
        return false if now.empty? || before.empty?
        # A one-word follow-up is not evidence of anything.
        return false if now.size < 3

        (now & before).size.to_f / now.size >= overlap
      end

      # Enough shared vocabulary to be about the same thing, without being the
      # same sentence. A reframing opener on an unrelated question is just a
      # question.
      def shares_topic?(text, previous)
        now = content_words(text)
        before = content_words(previous)
        return false if now.empty? || before.empty?

        now.intersect?(before)
      end

      def content_words(text)
        text.to_s.downcase.scan(/[a-z0-9_-]{2,}/) - STOP
      end

      def user?(turn)
        role = turn[:role] || turn['role']
        role.nil? || role.to_sym == :user
      end
    end
  end
end
