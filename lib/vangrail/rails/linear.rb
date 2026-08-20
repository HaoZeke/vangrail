# frozen_string_literal: true

require_relative '../linear_model'
require_relative '../rail'

module Vangrail
  module Rails
    # The fitted classifier, reading a model somebody trained on their own
    # traffic.
    #
    # On the corpus this repository can measure, it is the best detector here by
    # a wide margin and within two points of a published transformer:
    #
    #   hand-written rails                      39.5%
    #   naive Bayes over n-grams                67.0%
    #   this rail                               73.7%
    #   deberta-v3-base-prompt-injection-v2     75.3%
    #
    # all at the same false-alarm rate, cross-validated where fitted. Below one
    # false alarm in a hundred it beats the transformer, 27.0% against 21.1%,
    # which is the operating point a desk actually wants and the one a rule
    # stack cannot be asked about at all.
    #
    # It ships without a model, deliberately. Weights fitted on somebody else's
    # traffic are the thing this repository spent a long time measuring the cost
    # of, and the numbers above are for a model fitted on the corpus it was
    # scored against. Fit your own:
    #
    #   ruby script/train_linear.rb --emit model.json
    #
    # With no model configured the rail reports itself unchecked rather than
    # passing, because a detector that is not there must not look like a
    # detector that found nothing.
    class Linear < Rail
      def initialize(model: nil, path: nil, threshold: nil, name: 'linear', sides: %i[input context])
        super(name: name, sides: sides)
        @path = path
        @model = model || load_model(path)
        @threshold = threshold || @model&.threshold || 0.0
      end

      attr_reader :model, :threshold

      def cache_key(text, _context)
        return nil unless model

        "#{threshold}\n#{text}"
      end

      def decide(text, _context)
        return unchecked(missing_reason) unless model

        value = model.score(text)
        return pass if value <= threshold

        block(categories: ['linear'],
              reason: format('scores %<value>+.2f against a threshold of %<threshold>+.2f', value: value,
                                                                                            threshold: threshold))
      end

      private

      def load_model(path)
        path ||= ENV.fetch('GUARDRAILS_LINEAR_MODEL', nil)
        return nil if path.nil? || path.to_s.strip.empty?

        LinearModel.load(path)
      rescue StandardError => e
        @load_error = "#{path}: #{e.class.name.split('::').last}: #{e.message}"
        nil
      end

      def missing_reason
        return "linear model could not be read (#{@load_error})" if @load_error

        'no linear model configured: set GUARDRAILS_LINEAR_MODEL, or fit one with script/train_linear.rb'
      end
    end
  end
end
