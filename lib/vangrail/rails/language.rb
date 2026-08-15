# frozen_string_literal: true

require_relative '../nlp'
require_relative '../rail'

module Vangrail
  module Rails
    # Reports that a page or a question is in a language nothing here can read.
    #
    # Every other deterministic rail in this gem is a rule about English or
    # Dutch words. Handed a page in German, all of them return passed, and an
    # application reading that result cannot tell "checked and clean" from "the
    # checks do not apply to this text". That is precisely the distinction this
    # gem promises to keep, so the promise has to hold across languages too,
    # and on the question as well as on the retrieved page.
    #
    # So this rail never blocks. A page in an unsupported language is not an
    # attack, and refusing it would break a site that has one; what it is, is
    # unchecked, and `certain? == false` is the word for that. An application
    # reporting a safety posture can then route the page to a model rail, to a
    # human, or to nothing, knowing which it is doing.
    #
    # Below the floor it says nothing at all. A six-word question is not
    # evidence of a language, and marking every short turn uncertain would turn
    # the posture into noise, which is a different way of making it useless.
    class Language < Rail
      def initialize(supported: NLP::LANGUAGES, floor: NLP::LANGUAGE_FLOOR,
                     name: 'language', sides: %i[input context])
        super(name: name, sides: sides)
        @supported = Array(supported).map(&:to_sym)
        @floor = floor
      end

      attr_reader :supported, :floor

      def offline?
        true
      end

      def posture?
        true
      end

      def cache_key(text, _context)
        "#{supported.join('+')}\n#{text}"
      end

      def call(text, _context)
        reason = unread_reason(text)
        return unchecked(reason) if reason

        pass
      end

      private

      # Clause by clause: a German paragraph inside an English page is
      # unread even when the function words of the page as a whole are
      # English. The twelve-token floor still applies per clause, so a
      # short question stays quiet.
      def unread_reason(text)
        whole = classify(text)
        return whole if whole

        spans = NLP.clauses(text)
        return nil if spans.size <= 1

        spans.each do |span|
          reason = classify(span)
          return reason if reason
        end
        nil
      end

      def classify(span)
        tokens = NLP.words(span)
        return nil if tokens.size < floor

        found = NLP.language(span)
        return nil if supported.include?(found)
        # Named unread (Cavnar-Trenkle) is evidence even in the
        # twelve-to-twenty-three token band. An unidentified short
        # handbook sentence is not.
        return nil if tokens.size < (floor * 2) && !NLP.named_foreign?(span, supported)

        "text is not in a language this engine reads (#{supported.join(', ')}); " \
          'the deterministic rails do not apply to it'
      end
    end
  end
end
