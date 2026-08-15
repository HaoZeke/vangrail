# frozen_string_literal: true

require_relative '../completion'
require_relative '../rail'

module Vangrail
  module Rails
    # Reads how surprised a model is by the text, and blocks the span that is
    # not language.
    #
    # The optimised attacks in the literature do not produce sentences. A
    # gradient-search suffix reads like a hash with punctuation in it, and it
    # works on the model while meaning nothing to a reader. No pattern catches
    # it, because there is no pattern: the string is different every time it is
    # searched for. What it has instead is a signature that is hard to remove
    # while keeping the attack, which is that a language model finds it wildly
    # improbable.
    #
    # So the check is the model's own log probabilities, which is the published
    # detector for exactly this family. It needs an endpoint that will echo a
    # prompt and score it, and many will not; when that is the case this rail
    # reports uncertain and the deployment knows the family is uncovered rather
    # than believing it is handled.
    #
    # Windowed rather than averaged over the whole text, because an attack is a
    # short span inside an ordinary question. Twenty improbable tokens after a
    # hundred readable ones barely move the mean, and the window is what keeps
    # the signal from being diluted by the sentence the attacker wrapped it in.
    #
    # The threshold is not a constant of nature. Log probabilities depend on the
    # model, its tokenizer, and its quantisation, so the default here is a
    # starting point and script/perplexity_probe.rb is what turns it into a
    # measured number for the endpoint in use. A deployment that has not run it
    # is running an uncalibrated detector, and this rail is off by default for
    # that reason as much as for the round trip.
    class Perplexity < Rail
      # Mean negative log likelihood per token, in nats. Ordinary prose under a
      # small instruct model sits around 2 to 4; a gradient-search suffix sits
      # far above it. Calibrate before trusting.
      THRESHOLD = 7.0

      # Tokens per window. Short enough that a twenty-token suffix fills one,
      # long enough that a rare proper noun does not.
      WINDOW = 16

      # Below this many scored tokens there is no window worth taking, and a
      # three-word question is not evidence of anything.
      FLOOR = 8

      attr_reader :completion, :threshold, :window

      def initialize(completion:, threshold: THRESHOLD, window: WINDOW, floor: FLOOR,
                     name: 'perplexity', sides: %i[input context])
        super(name: name, sides: sides)
        @completion = completion
        @threshold = threshold
        @window = window
        @floor = floor
      end

      def offline?
        false
      end

      def cache_key(text, _context)
        "#{completion.model}\n#{threshold}\n#{window}\n#{text}"
      end

      def call(text, _context)
        body = text.to_s
        return pass if body.strip.empty?

        score = worst_window(body)
        return pass if score.nil? || score < threshold

        block(categories: ['high_perplexity'],
              reason: format('a span of %<window>d tokens scores %<score>.1f nats against a threshold of ' \
                             '%<threshold>.1f: this is not language',
                             window: window, score: score, threshold: threshold))
      rescue Error => e
        unchecked("perplexity check did not run: #{e.message}")
      end

      # The highest mean negative log likelihood of any window, or nil when the
      # text is too short to have one. Raises what the transport raises, so a
      # probe script sees the error and a rail sees a Result.
      def worst_window(text)
        logprobs = completion.token_logprobs(text)
        return nil if logprobs.size < @floor

        size = [window, logprobs.size].min
        (0..(logprobs.size - size)).map do |start|
          slice = logprobs[start, size]
          -slice.sum / slice.size
        end.max
      end
    end
  end
end
