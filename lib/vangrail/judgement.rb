# frozen_string_literal: true

module Vangrail
  # What to do with a posterior, and what the numbers were.
  #
  # A Result answers "did a rail stop this". A Judgement answers a different
  # question: given everything that ran, how likely is it that this text is an
  # attack, and is that likely enough to act on. The two are not interchangeable
  # and the second is the one an operator can set a policy against.
  Judgement = Struct.new(:posterior, :prior, :bits, :contributions, :certain, :action, :side,
                         :skipped, keyword_init: true) do
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

    def to_h
      {
        'side' => side.to_s,
        'prior' => prior,
        'posterior' => posterior.round(6),
        'bits' => bits.round(2),
        'action' => action.to_s,
        'certain' => certain?,
        'fired' => fired.map { |c| { 'rail' => c[:rail], 'bits' => c[:bits].round(2) } },
        'skipped' => (skipped unless skipped.empty?)
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

  # Assigned outside the struct body, because a constant written inside a
  # Struct.new block lands in the enclosing module rather than in the struct.
  Policy::DEFAULT = Policy.new(block_at: 0.5, review_at: 0.05)
end
