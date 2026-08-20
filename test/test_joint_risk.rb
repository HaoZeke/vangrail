# frozen_string_literal: true

require_relative 'helper'
require_relative 'support/joint_risk_fixture'

class TestJointRisk < Minitest::Test
  include JointRiskFixture

  def test_optional_readers_abstain_when_the_provider_is_absent
    reader = Vangrail::OptionalReader.new(
      id: :encoder,
      model_id: 'encoder-v1',
      feature_schema: ['score'],
    )

    result = reader.score('page', side: :context)

    assert_predicate result, :abstained?
    assert_match(/not configured/, result.reason)
    assert_empty result.scores
  end

  def test_optional_readers_validate_provider_identity
    provider = lambda do |_text, side:, **_context|
      {
        model_id: 'different-model',
        feature_schema: ['score'],
        side: side,
        scores: { score: 0.8 },
      }
    end
    reader = Vangrail::OptionalReader.new(
      id: :encoder,
      model_id: 'encoder-v1',
      feature_schema: ['score'],
      provider: provider,
    )

    result = reader.score('page', side: :context)

    assert_predicate result, :invalid?
    assert_match(/model identity/, result.reason)
  end

  def test_joint_model_combines_scores_interactions_context_and_uncertainty
    model = Vangrail::JointRiskModel.new(Vangrail::JointRiskArtifact.new(artifact_data))
    results = [score(:lexical, 'lexical-v1', 0.5), score(:encoder, 'encoder-v1', 1.0)]

    assert_raises(ArgumentError) do
      model.estimate(results, side: :context, origin: :data, language: :en, domain: :handbook)
    end
    estimate = model.estimate(
      results,
      side: :context,
      origin: :data,
      language: :en,
      domain: :handbook,
      prior: 0.5,
      confidence: 0.95,
    )

    expected_logit = -2.0 + 0.5 + 2.0 + 0.25 + 0.2 + 0.1
    expected = 1.0 / (1.0 + Math.exp(-expected_logit))

    assert_predicate estimate, :valid?
    assert_in_delta expected, estimate.posterior, 1e-12
    assert_operator estimate.interval.first, :<, estimate.posterior
    assert_operator estimate.interval.last, :>, estimate.posterior
    assert_equal 'calibration-v1', estimate.calibration_id
    assert_equal 2, estimate.cost['calls']
  end

  def test_missing_mismatched_and_out_of_range_scores_abstain
    model = Vangrail::JointRiskModel.new(Vangrail::JointRiskArtifact.new(artifact_data))
    lexical = score(:lexical, 'lexical-v1', 0.5)

    missing = model.estimate(
      [lexical], side: :context, origin: :data, language: :en, domain: :handbook, prior: 0.5
    )
    mismatch = model.estimate(
      [lexical, score(:encoder, 'wrong', 1.0)],
      side: :context, origin: :data, language: :en, domain: :handbook, prior: 0.5,
    )
    out_of_range = model.estimate(
      [lexical, score(:encoder, 'encoder-v1', 9.0)],
      side: :context, origin: :data, language: :en, domain: :handbook, prior: 0.5,
    )

    [missing, mismatch, out_of_range].each { |estimate| assert_predicate estimate, :abstained? }
    assert_match(/missing reader encoder/, missing.reason)
    assert_match(/model identity/, mismatch.reason)
    assert_match(/outside.*range/, out_of_range.reason)
  end

  def test_interval_crossing_a_policy_boundary_becomes_an_uncertain_restriction
    model = Vangrail::JointRiskModel.new(Vangrail::JointRiskArtifact.new(artifact_data))
    estimate = model.estimate(
      [score(:lexical, 'lexical-v1', 0.5), score(:encoder, 'encoder-v1', 1.0)],
      side: :context, origin: :data, language: :en, domain: :handbook, prior: 0.5,
    )

    restriction = estimate.restriction(Vangrail::Policy::DEFAULT)

    refute_predicate restriction, :certain?
    assert_predicate restriction, :allowed?
    assert_match(/crosses a policy boundary/, restriction.reason)
  end

  def test_artifact_validation_rejects_unknown_or_oversized_models
    unknown = artifact_data.merge('schema' => 'joint-risk-v99')
    oversized = artifact_data.merge('feature_schema' => (1..257).map { |index| "f#{index}" })

    assert_raises(Vangrail::ProtocolError) { Vangrail::JointRiskArtifact.new(unknown) }
    assert_raises(Vangrail::ProtocolError) { Vangrail::JointRiskArtifact.new(oversized) }
  end

  def test_platt_calibration_is_part_of_the_posterior_and_interval
    calibrated = artifact_data.merge(
      'calibration' => {
        'id' => 'calibration-v2',
        'method' => 'platt',
        'intercept' => -0.4,
        'slope' => 1.5,
        'covariance_diagonal' => { 'intercept' => 0.01, 'slope' => 0.04 },
      },
    )
    model = Vangrail::JointRiskModel.new(Vangrail::JointRiskArtifact.new(calibrated))
    estimate = model.estimate(
      [score(:lexical, 'lexical-v1', 0.5), score(:encoder, 'encoder-v1', 1.0)],
      side: :context, origin: :data, language: :en, domain: :handbook, prior: 0.5,
    )
    base_logit = -2.0 + 0.5 + 2.0 + 0.25 + 0.2 + 0.1
    expected = 1.0 / (1.0 + Math.exp(-(-0.4 + (1.5 * base_logit))))

    assert_in_delta expected, estimate.posterior, 1e-12
    assert_equal 'calibration-v2', estimate.calibration_id
    assert_operator estimate.interval.first, :<, estimate.posterior
    assert_operator estimate.interval.last, :>, estimate.posterior
  end

  def test_joint_assessor_runs_optional_readers_without_runtime_model_dependencies
    provider = lambda do |model_id, value|
      lambda do |_text, side:, **_context|
        {
          model_id: model_id,
          feature_schema: ['score'],
          side: side,
          scores: { score: value },
          cost: { calls: 1 },
        }
      end
    end
    readers = [
      Vangrail::OptionalReader.new(
        id: :lexical,
        model_id: 'lexical-v1',
        feature_schema: ['score'],
        provider: provider.call('lexical-v1', 0.5),
      ),
      Vangrail::OptionalReader.new(
        id: :encoder,
        model_id: 'encoder-v1',
        feature_schema: ['score'],
        provider: provider.call('encoder-v1', 1.0),
      ),
    ]
    assessor = Vangrail::JointAssessor.new(
      readers: readers,
      model: Vangrail::JointRiskModel.new(Vangrail::JointRiskArtifact.new(artifact_data)),
    )

    estimate = assessor.assess(
      'page',
      side: :context,
      origin: :data,
      language: :en,
      domain: :handbook,
      prior: 0.5,
    )

    assert_predicate estimate, :valid?
    assert_equal 2, estimate.cost['calls']
  end
end
