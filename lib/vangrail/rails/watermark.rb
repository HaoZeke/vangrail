# frozen_string_literal: true

require_relative '../rail'
require_relative '../watermark'

module Vangrail
  module Rails
    # Marks the answer as generated, in a format a machine can read.
    #
    # The obligation is Article 50(2) of the AI Act: a provider of a generative
    # system marks its output so it is detectable as artificially generated, and
    # does so effectively, interoperably, robustly and reliably as far as
    # technically feasible. Vangrail::Watermark carries the format and the
    # argument for it; this is the rail that puts it on the output side of an
    # engine, beside the rails that read the same text.
    #
    #   Vangrail::Engine.new(
    #     output: [Vangrail::Rails::Watermark.new(key: ENV['ASK_WATERMARK_KEY'],
    #                                             issuer: 'surf/handbook-ask')]
    #   )
    #
    # It runs last by convention, after the rails that might rewrite the answer:
    # a redaction applied to marked text leaves a mark covering words that are
    # no longer there, and the mark would then fail its own verification. Order
    # the output list with this at the end and that cannot happen.
    #
    # The result is :modified, because the rail did rewrite the text and saying
    # otherwise would make a rail lie about what it did. An application whose
    # interface flags edited answers to the reader should route on the category
    # rather than on the status: `watermark` is disclosure, not redaction.
    #
    # With no key it still marks. The disclosure half of Article 50 is the magic
    # bytes, which need no secret, and a rail that does nothing until somebody
    # provisions a key is a rail that ships turned off. The key buys attribution
    # on top: with one, a mark verifies as this issuer's and cannot be lifted off
    # one answer onto another.
    class Watermark < Rail
      attr_reader :key, :issuer

      def initialize(key: nil, issuer: nil, name: 'watermark', sides: [:output])
        super(name: name, sides: sides)
        @key = key
        @issuer = issuer
      end

      def signed?
        !key.nil? && !key.to_s.empty?
      end

      # Not mid-stream. The mark covers a finished paragraph, and a paragraph
      # that is still arriving would be marked once per chunk, each mark
      # covering different words and each one rewriting text the reader can
      # already see. StreamGuard marks at `finish`, where the answer is whole.
      def incremental?
        false
      end

      # Same text, same key, same mark, so a repeat costs one HMAC and no
      # second run of selectors.
      def cache_key(text, _context)
        text
      end

      def decide(text, _context)
        marked = Vangrail::Watermark.mark(text, key: key, issuer: issuer)
        return pass if marked == text

        modify(marked, categories: categories, reason: reason)
      end

      private

      def categories
        signed? ? %w[watermark watermark:signed] : %w[watermark watermark:unsigned]
      end

      def reason
        signed? ? "marked as generated, signed as #{issuer || 'unnamed issuer'}" : 'marked as generated, unsigned'
      end
    end
  end
end
