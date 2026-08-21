# frozen_string_literal: true

require_relative 'origin'

module Vangrail
  # What to do with a posterior, and what the numbers were.
  #
  # A Result answers "did a rail stop this". A Judgement answers a different
  # question: given everything that ran, how likely is it that this text is an
  # attack, and is that likely enough to act on. The two are not interchangeable
  # and the second is the one an operator can set a policy against.
  Judgement = Struct.new(:posterior, :prior, :bits, :contributions, :certain, :action, :side,
                         :skipped, :origin, keyword_init: true) do
    def block?
      action == :block
    end

    def review?
      action == :review
    end

    def allow?
      action == :allow
    end

    def certain?
      certain
    end

    # The rails that fired, most telling first, which is what a person reading
    # a flagged page wants before anything else.
    def fired
      contributions.select { |c| c[:fired] }.sort_by { |c| -c[:bits] }
    end

    # How far the evidence moved the odds, as a multiplier. Bits are the honest
    # unit and this is the readable one.
    def factor
      2**bits
    end

    # Rails not run because the action was already settled: no remaining
    # evidence could have changed it. Different in kind from a rail that could
    # not run, which is why this is a separate field from `certain?`.
    def skipped
      self[:skipped] || []
    end

    def channel
      origin&.channel
    end

    # The rails that said nothing, as one entry rather than a list of them.
    #
    # Their bits are what pushes a clean page below its prior, so a payload
    # carrying only the rails that fired shows a posterior under the prior with
    # nothing to account for it: the numbers on the page do not add up to the
    # decision the page is reporting. One entry keeps them adding up without
    # listing thirty rails that had nothing to say.
    def silence
      quiet = contributions.reject { |c| c[:fired] }
      return nil if quiet.empty?

      { 'rails' => quiet.size, 'bits' => quiet.sum { |c| c[:bits] }.round(2) }
    end

    def to_h
      {
        'side' => side.to_s,
        'origin' => origin&.to_s,
        'channel' => channel&.to_s,
        'prior' => prior,
        'posterior' => posterior.round(6),
        'bits' => bits.round(2),
        'action' => action.to_s,
        'certain' => certain?,
        'fired' => fired.map { |c| { 'rail' => c[:rail], 'bits' => c[:bits].round(2) } },
        'silent' => silence,
        'skipped' => (skipped unless skipped.empty?),
      }.compact
    end

    def to_s
      parts = [format('%<action>s p=%<posterior>.4f (prior %<prior>g, %<bits>+.1f bits)',
                      action: action, posterior: posterior, prior: prior, bits: bits)]
      parts << "fired: #{fired.map { |c| c[:rail] }.join(', ')}" unless fired.empty?
      parts << 'uncertain' unless certain?
      parts.join(' ')
    end
  end

  # Where the two lines are drawn between allowing, reviewing, and blocking.
  #
  # Three actions rather than two, because the middle one is what a posterior
  # makes possible and a yes-or-no rail cannot express. Most of the interesting
  # traffic on a documentation desk lands there: one rail fired, the base rate
  # is low, and the honest answer is that this page is a hundred times more
  # suspicious than average and still probably fine. Blocking it costs a reader
  # their answer; ignoring it wastes the detection. Queueing it costs somebody a
  # minute.
  #
  # The defaults are stated as what they are: a starting policy, not a finding.
  # What they should be depends on what a false block costs against what a
  # missed injection costs, and that is a deployment's judgement rather than a
  # library's.
  Policy = Struct.new(:block_at, :review_at, keyword_init: true) do
    def action_for(posterior)
      return :block if posterior >= block_at
      return :review if posterior >= review_at

      :allow
    end
  end

  class Policy
    # The two lines, derived from what the three outcomes cost instead of
    # chosen.
    #
    # A posterior is only half an answer: acting on it needs to know what being
    # wrong is worth in each direction, and that is a fact about the deployment
    # rather than about the text. Written out, the decision rule is the ordinary
    # one from decision theory. Allowing a page costs the chance it was an
    # attack times what a missed attack costs. Blocking costs the chance it was
    # fine times what a wrong block costs a reader. Sending it to a person costs
    # what a minute of their time costs, whatever the page turns out to be.
    #
    # Choosing the cheapest of the three gives both thresholds directly:
    # reviewing beats allowing above `review / missed_attack`, and blocking
    # beats reviewing above `1 - review / false_block`.
    #
    #   Policy.from_costs(missed_attack: 1000, false_block: 10, review: 1)
    #   # => block above 0.9, review above 0.001
    #
    # The units cancel, so they can be euros, minutes, or anything else applied
    # consistently. What they cannot be is unstated: a threshold with no cost
    # behind it is a preference, and this is the arithmetic that turns the
    # preference into a claim somebody can argue with.
    def self.from_costs(missed_attack:, false_block:, review: nil)
      raise ArgumentError, 'costs must be positive' unless [missed_attack, false_block].all?(&:positive?)

      # With no human in the loop there is one line, and it is the classic
      # threshold: block when the expected cost of allowing exceeds the
      # expected cost of blocking.
      return two_way(missed_attack, false_block) if review.nil?

      raise ArgumentError, 'review cost must be positive' unless review.positive?

      review_at = review.fdiv(missed_attack)
      block_at = 1 - review.fdiv(false_block)
      # Reviewing everything costs more than being wrong: there is no band, and
      # saying so beats silently inverting the thresholds.
      return two_way(missed_attack, false_block) if review_at >= block_at

      new(block_at: block_at, review_at: review_at)
    end

    def self.two_way(missed_attack, false_block)
      threshold = false_block.fdiv(false_block + missed_attack)
      new(block_at: threshold, review_at: threshold)
    end
  end

  # Assigned outside the struct body, because a constant written inside a
  # Struct.new block lands in the enclosing module rather than in the struct.
  Policy::DEFAULT = Policy.new(block_at: 0.5, review_at: 0.05)
end
