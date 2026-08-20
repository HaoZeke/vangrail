# frozen_string_literal: true

require_relative 'helper'

class TestJointRisk < Minitest::Test
  def artifact_data
    {
      'schema' => 'vangrail-joint-risk-v1',
      'id' => 'joint-test-v1',
      'posterior_method' => 'laplace_diagonal',
      'training_prevalence' => 0.5,
      'normalization' => { 'id' => 'vangrail-nlp-v1' },
      'feature_schema' => %w[lexical.score encoder.score],
      'readers' => {
        'lexical' => { 'model_id' => 'lexical-v1', 'feature_schema' => ['score'] },
        'encoder' => { 'model_id' => 'encoder-v1', 'feature_schema' => ['score'] },
      },
      'intercept' => -2.0,
      'coefficients' => { 'lexical.score' => 1.0, 'encoder.score' => 2.0 },
      'interactions' => { 'lexical.score*encoder.score' => 0.5 },
      'context_offsets' => { 'side:context' => 0.2, 'origin:data' => 0.1 },
      'covariance_diagonal' => {
        'intercept' => 0.04,
        'lexical.score' => 0.09,
        'encoder.score' => 0.36,
        'lexical.score*encoder.score' => 0.01,
      },
      'score_ranges' => {
        'lexical.score' => [-3.0, 3.0],
        'encoder.score' => [-3.0, 3.0],
      },
      'supported' => {
        'sides' => %w[input context],
        'origins' => %w[user data],
        'languages' => %w[en nl],
        'domains' => ['handbook'],
      },
      'calibration' => { 'id' => 'calibration-v1', 'method' => 'identity' },
      'training_manifest_sha256' => 'a' * 64,
    }
  end

  def score(reader, model, value)
    Vangrail::ScoreResult.ok(
      reader_id: reader,
      model_id: model,
      feature_schema: ['score'],
      side: :context,
      scores: { score: value },
      cost: { latency_ms: 1.0, calls: 1 },
    )
  end

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
end
