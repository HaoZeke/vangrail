# frozen_string_literal: true

require_relative 'helper'

class TestRiskScenario < Minitest::Test
  def test_beta_binomial_prevalence_is_immutable_and_reports_uncertainty
    prior = Vangrail::BetaBinomialPrior.new(alpha: 1, beta: 9)

    updated = prior.adjudicate(:attack)
    low, high = prior.interval(confidence: 0.95)

    assert_in_delta 0.1, prior.mean
    assert_operator low, :<, prior.mean
    assert_operator high, :>, prior.mean
    assert_in_delta 2.0 / 11, updated.mean
    assert_in_delta 0.1, prior.mean
    assert_predicate prior, :frozen?
    assert_raises(ArgumentError) { prior.adjudicate(:detector_positive) }
  end

  def test_dirichlet_composition_is_immutable_and_normalized
    prior = Vangrail::DirichletThreatPrior.new(override: 2, exfiltration: 1)

    updated = prior.adjudicate(:exfiltration)

    assert_in_delta 2.0 / 3, prior.mean.fetch('override')
    assert_in_delta 1.0 / 3, prior.mean.fetch('exfiltration')
    assert_in_delta 0.5, updated.mean.fetch('override')
    assert_in_delta 0.5, updated.mean.fetch('exfiltration')
    assert_predicate prior, :frozen?
    assert_raises(ArgumentError) { prior.adjudicate(:unknown) }
  end

  def test_scenario_updates_only_from_adjudicated_labels
    scenario = Vangrail::RiskScenario.new(
      prevalence: Vangrail::BetaBinomialPrior.new(alpha: 1, beta: 9),
      threats: Vangrail::DirichletThreatPrior.new(override: 1, exfiltration: 1),
    )

    attack = scenario.adjudicate(label: :attack, family: :override)
    benign = scenario.adjudicate(label: :benign)

    assert_in_delta 0.1, scenario.prior
    assert_equal({ 'override' => 0.5, 'exfiltration' => 0.5 }, scenario.threat_mixture)
    assert_operator attack.prior, :>, scenario.prior
    assert_operator benign.prior, :<, scenario.prior
    assert_operator attack.threat_mixture.fetch('override'), :>, scenario.threat_mixture.fetch('override')
    assert_equal scenario.threat_mixture, benign.threat_mixture
    assert_raises(ArgumentError) { scenario.adjudicate(label: :attack) }
    assert_raises(ArgumentError) { scenario.adjudicate(label: :detector_positive, family: :override) }
  end
end
