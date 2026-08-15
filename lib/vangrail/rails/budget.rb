# frozen_string_literal: true

require_relative '../rail'

module Vangrail
  module Rails
    # Refuses text too large to be a question.
    #
    # The cost of answering is paid by whoever runs the endpoint, and a public
    # desk gives anybody a way to spend it. A megabyte pasted into the box is
    # not a question: it is a bill, and on a metered endpoint it is somebody
    # else's bill. The same size also dilutes whatever the instructions said,
    # which is the mechanism the many-shot work measured, so the limit is worth
    # having twice over.
    #
    # Characters rather than tokens, because counting tokens means shipping a
    # tokeniser, and a tokeniser is a dependency and a model-specific one. The
    # ratio is close enough for a limit: roughly four characters a token for
    # English prose, less for code.
    #
    #   Rails::Budget.new(max_characters: 8_000)
    #
    # A separate, larger limit applies to retrieved documents, which are
    # legitimately longer than anything a reader types and are usually clipped
    # by the retrieval step already. Setting it to nil turns that side off.
    #
    # Blocks rather than truncating. A truncated question is a different
    # question, and answering a different question well is worse than saying
    # the box has a limit.
    class Budget < Rail
      DEFAULT_INPUT = 8_000
      DEFAULT_CONTEXT = 60_000

      attr_reader :max_characters, :max_context

      def initialize(max_characters: DEFAULT_INPUT, max_context: DEFAULT_CONTEXT,
                     name: 'budget', sides: %i[input context])
        super(name: name, sides: sides)
        @max_characters = max_characters
        @max_context = max_context
      end

      def offline?
        true
      end

      def language_agnostic?
        true
      end

      def cache_key(text, context)
        "#{context[:side]}:#{text.to_s.length}"
      end

      def call(text, context)
        limit = context[:side] == :context ? max_context : max_characters
        return pass if limit.nil?

        size = text.to_s.length
        return pass if size <= limit

        block(categories: ['over_budget'],
              reason: "#{size} characters, over the #{limit} allowed for #{context[:side]}")
      end
    end
  end
end
