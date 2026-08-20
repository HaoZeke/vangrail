# frozen_string_literal: true

require_relative 'helper'
require_relative 'support/joint_risk_fixture'

class TestJointRiskMixture < Minitest::Test
  include JointRiskFixture

  def test_deployment_scenario_separates_prevalence_from_threat_composition
    scenario = Vangrail::RiskScenario.new(
      prevalence: Vangrail::BetaBinomialPrior.new(alpha: 50, beta: 50),
      threats: Vangrail::DirichletThreatPrior.new(override: 9, exfiltration: 1),
    )
    estimate = estimate_for(scenario)

    assert_predicate estimate, :valid?
    assert_in_delta expected_posterior, estimate.posterior, 1e-12
    assert_equal scenario.threat_mixture, estimate.context['threat_mixture']
    assert_operator estimate.interval.first, :<, estimate.posterior
    assert_operator estimate.interval.last, :>, estimate.posterior
    assert_raises(ArgumentError) { estimate_for(scenario, prior: 0.5) }
  end

  def test_unknown_deployment_threat_families_abstain
    scenario = Vangrail::RiskScenario.new(
      prevalence: Vangrail::BetaBinomialPrior.new(alpha: 1, beta: 1),
      threats: Vangrail::DirichletThreatPrior.new(unknown: 1),
    )

    estimate = estimate_for(scenario)

    assert_predicate estimate, :abstained?
    assert_match(/threat families/, estimate.reason)
  end

  def test_artifact_rejects_incoherent_threat_models
    composition = artifact_data.fetch('threat_model').merge(
      'training_composition' => { 'override' => 0.8, 'exfiltration' => 0.8 },
    )
    missing_offset = artifact_data.fetch('threat_model').merge(
      'log_likelihood_offsets' => { 'override' => 0.0 },
    )

    assert_raises(Vangrail::ProtocolError) do
      Vangrail::JointRiskArtifact.new(artifact_data.merge('threat_model' => composition))
    end
    assert_raises(Vangrail::ProtocolError) do
      Vangrail::JointRiskArtifact.new(artifact_data.merge('threat_model' => missing_offset))
    end
  end

  private

  def estimate_for(scenario, prior: nil)
    model = Vangrail::JointRiskModel.new(Vangrail::JointRiskArtifact.new(artifact_data))
    results = [score(:lexical, 'lexical-v1', 0.5), score(:encoder, 'encoder-v1', 1.0)]
    model.estimate(
      results,
      side: :context,
      origin: :data,
      language: :en,
      domain: :handbook,
      prior: prior,
      scenario: scenario,
    )
  end

  def expected_posterior
    training_weight = (0.5 * 2.0) + (0.5 * 0.5)
    deployment_weight = (0.9 * 2.0) + (0.1 * 0.5)
    base_logit = -2.0 + 0.5 + 2.0 + 0.25 + 0.2 + 0.1
    1.0 / (1.0 + Math.exp(-(base_logit + Math.log(deployment_weight / training_weight))))
  end
end
