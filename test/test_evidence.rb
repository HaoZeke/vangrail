# frozen_string_literal: true

require_relative 'helper'

# The arithmetic that turns a set of yes-or-no rails into a probability, and the
# four properties that make it worth doing at all: the base rate matters, weak
# evidence adds up, silence counts, and a rail that did not run counts for
# nothing.
class TestEvidence < Minitest::Test
  include GuardrailsTest

  # A strong rail and a weak one, with round numbers so every expectation below
  # is arithmetic rather than a fixture.
  STRONG = Vangrail::Evidence.new(rail: 'strong', group: 'strong',
                                  attacks_caught: 90, attacks: 100,
                                  benign_flagged: 1, benign: 100)
  WEAK = Vangrail::Evidence.new(rail: 'weak', group: 'weak',
                                attacks_caught: 50, attacks: 100,
                                benign_flagged: 20, benign: 100)
  TABLE = { 'strong' => STRONG, 'weak' => WEAK }.freeze

  def posterior(prior, observations, evidence: TABLE)
    Vangrail::Posterior.combine(prior: prior, observations: observations, evidence: evidence).first
  end

  # --- the rates ---

  def test_rates_are_smoothed_so_a_perfect_score_is_not_infinite_evidence
    perfect = Vangrail::Evidence.new(rail: 'perfect', attacks_caught: 60, attacks: 60,
                                     benign_flagged: 0, benign: 60)

    assert_operator perfect.detection, :<, 1.0
    assert_operator perfect.false_alarm, :>, 0.0
    assert_predicate perfect.bits(true), :finite?
    # And the evidence it carries is bounded by how much was measured: sixty
    # clean documents cannot demonstrate a rate below roughly one in a hundred.
    assert_operator perfect.false_alarm, :>, 0.005
  end

  def test_a_rail_that_fires_more_on_attacks_than_on_prose_carries_positive_bits
    assert_operator STRONG.bits(true), :>, 0
    assert_operator STRONG.bits(false), :<, 0
    assert_operator STRONG.bits(true), :>, WEAK.bits(true)
  end

  # --- the base rate, which is the point ---

  def test_the_same_evidence_means_different_things_at_different_base_rates
    balanced = posterior(0.5, { 'strong' => true })
    realistic = posterior(1e-4, { 'strong' => true })

    assert_operator balanced, :>, 0.9
    assert_operator realistic, :<, 0.1
  end

  # The arithmetic every deployment inherits and almost none is shown: a rail
  # with a one percent false-alarm rate, firing on a page drawn from traffic
  # where one page in ten thousand is poisoned, is wrong far more often than it
  # is right.
  def test_a_single_hit_at_a_realistic_base_rate_is_mostly_a_false_alarm
    assert_operator posterior(1e-4, { 'strong' => true }), :<, 0.02
  end

  def test_the_bits_needed_to_reach_a_verdict_are_computable
    bits = Vangrail::Posterior.required_bits(prior: 1e-4, target: 0.5)

    assert_in_delta 13.29, bits, 0.01
    # No single rail measured on a corpus of this size comes close.
    assert_operator STRONG.bits(true), :<, bits
  end

  # The design rule that falls out of it: to carry a block alone, a rail would
  # need a false-alarm rate no hand-built corpus can demonstrate.
  def test_a_lone_rail_would_need_an_undemonstrable_false_alarm_rate
    needed = Vangrail::Posterior.false_alarm_needed(prior: 1e-4, detection: 0.9, target: 0.5)

    assert_operator needed, :<, 1e-4
    # Showing a rate that low needs a benign corpus in the tens of thousands.
    assert_operator (0.5 / needed), :>, 5000
  end

  # --- accumulation, which OR cannot express ---

  def test_two_weak_rails_say_more_than_either_alone
    one = posterior(0.01, { 'weak' => true })
    two = posterior(0.01, { 'weak' => true, 'strong' => true })

    assert_operator two, :>, one
  end

  def test_silence_is_evidence_and_points_the_other_way
    quiet = posterior(0.01, { 'strong' => false, 'weak' => false })

    assert_operator quiet, :<, 0.01
  end

  # --- abstention ---

  # A rail that could not decide is not a rail that found nothing. Folding the
  # two together turns a refused connection into evidence of innocence.
  def test_a_rail_that_did_not_run_moves_nothing
    absent = posterior(0.01, { 'strong' => nil, 'weak' => nil })
    silent = posterior(0.01, { 'strong' => false, 'weak' => false })

    assert_in_delta 0.01, absent, 1e-12
    assert_operator silent, :<, absent
  end

  def test_a_rail_with_no_measured_operating_point_moves_nothing
    unmeasured = Vangrail::Evidence.new(rail: 'new', attacks_caught: 0, attacks: 0,
                                        benign_flagged: 0, benign: 0)
    table = TABLE.merge('new' => unmeasured)

    refute_predicate unmeasured, :measured?
    assert_in_delta 0.01, posterior(0.01, { 'new' => true }, evidence: table), 1e-12
  end

  # --- correlation ---

  # Three rails firing on the same sentence for the same reason are one
  # observation reported three times. Summing them is how a combination rule
  # talks itself into certainty.
  def test_rails_measured_to_agree_speak_once
    twin_a = Vangrail::Evidence.new(rail: 'twin_a', group: 'twins', attacks_caught: 90, attacks: 100,
                                    benign_flagged: 1, benign: 100)
    twin_b = Vangrail::Evidence.new(rail: 'twin_b', group: 'twins', attacks_caught: 90, attacks: 100,
                                    benign_flagged: 1, benign: 100)
    table = { 'twin_a' => twin_a, 'twin_b' => twin_b }

    both = posterior(0.01, { 'twin_a' => true, 'twin_b' => true }, evidence: table)
    one = posterior(0.01, { 'twin_a' => true }, evidence: table)

    assert_in_delta one, both, 1e-12
  end

  def test_the_group_is_spoken_for_by_its_strongest_witness
    contributions = Vangrail::Posterior.weigh({ 'strong' => true, 'weak' => true },
                                              { 'strong' => STRONG.dup.tap { |e| e.group = 'both' },
                                                'weak' => WEAK.dup.tap { |e| e.group = 'both' } })

    assert_equal 1, contributions.size
    assert_equal 'strong', contributions.first[:rail]
    assert_equal %w[strong weak], contributions.first[:spoke_for]
  end

  # --- guards ---

  def test_a_prior_of_zero_or_one_is_refused
    assert_raises(ArgumentError) { posterior(0.0, { 'strong' => true }) }
    assert_raises(ArgumentError) { posterior(1.0, { 'strong' => true }) }
  end

  def test_the_shipped_table_is_measured_and_positive_where_it_fires
    Vangrail::EvidenceData::ENTRIES.each do |entry|
      assert_predicate entry, :measured?, "#{entry.rail} has no measured operating point"
      assert_operator entry.bits(true), :>, 0,
                      "#{entry.rail} fires more often on ordinary text than on attacks in the corpus"
      assert_operator entry.bits(false), :<=, 0
    end
  end

  # --- policy ---

  def test_the_policy_draws_two_lines_rather_than_one
    policy = Vangrail::Policy::DEFAULT

    assert_equal :block, policy.action_for(0.9)
    assert_equal :review, policy.action_for(0.2)
    assert_equal :allow, policy.action_for(0.001)
  end

  # A threshold with no cost behind it is a preference. These come from what
  # being wrong is worth in each direction, which is a fact about the deployment
  # and an argument somebody can have.
  def test_thresholds_can_be_derived_from_what_being_wrong_costs
    policy = Vangrail::Policy.from_costs(missed_attack: 1000, false_block: 10, review: 1)

    assert_in_delta 0.9, policy.block_at, 1e-9
    assert_in_delta 0.001, policy.review_at, 1e-9
  end

  # The derivation, checked rather than asserted: at every posterior the action
  # the policy picks is the one with the lowest expected cost.
  def test_the_derived_policy_picks_the_cheapest_action_at_every_posterior
    missed = 1000.0
    wrong_block = 10.0
    review = 1.0
    policy = Vangrail::Policy.from_costs(missed_attack: missed, false_block: wrong_block, review: review)

    (0..100).each do |step|
      p = step / 100.0
      costs = { allow: p * missed, block: (1 - p) * wrong_block, review: review }
      cheapest = costs.min_by { |_, cost| cost }.first

      assert_in_delta costs[cheapest], costs[policy.action_for(p)], 1e-9,
                      "at p=#{p} the policy chose #{policy.action_for(p)} over #{cheapest}"
    end
  end

  def test_without_a_reviewer_there_is_one_line_and_it_is_the_classic_one
    policy = Vangrail::Policy.from_costs(missed_attack: 1000, false_block: 10)

    assert_in_delta 10.0 / 1010, policy.block_at, 1e-9
    assert_in_delta policy.block_at, policy.review_at, 1e-9
  end

  # A reviewer who costs more than being wrong is a reviewer nobody should call,
  # and saying so beats inverting the two thresholds silently.
  def test_a_review_dearer_than_the_mistakes_collapses_the_band
    policy = Vangrail::Policy.from_costs(missed_attack: 5, false_block: 100, review: 60)

    assert_in_delta policy.block_at, policy.review_at, 1e-9
  end

  def test_costs_have_to_be_positive
    assert_raises(ArgumentError) { Vangrail::Policy.from_costs(missed_attack: 0, false_block: 1) }
    assert_raises(ArgumentError) { Vangrail::Policy.from_costs(missed_attack: 1, false_block: -1) }
    assert_raises(ArgumentError) { Vangrail::Policy.from_costs(missed_attack: 1, false_block: 1, review: 0) }
  end
end
