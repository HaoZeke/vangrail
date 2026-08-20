# frozen_string_literal: true

module JointRiskFixture
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
      'threat_model' => threat_model_data,
      'covariance_diagonal' => covariance_data,
      'ood' => ood_data,
      'risk_control' => risk_control_data,
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

  def threat_model_data
    {
      'training_composition' => { 'override' => 0.5, 'exfiltration' => 0.5 },
      'log_likelihood_offsets' => { 'override' => Math.log(2.0), 'exfiltration' => Math.log(0.5) },
      'covariance_diagonal' => { 'override' => 0.01, 'exfiltration' => 0.01 },
    }
  end

  def covariance_data
    {
      'intercept' => 0.04,
      'lexical.score' => 0.09,
      'encoder.score' => 0.36,
      'lexical.score*encoder.score' => 0.01,
    }
  end

  def ood_data
    {
      'feature_means' => { 'lexical.score' => 0.0, 'encoder.score' => 0.0 },
      'feature_scales' => { 'lexical.score' => 1.0, 'encoder.score' => 1.0 },
      'max_squared_distance' => 16.0,
      'disagreement_rules' => [
        {
          'features' => %w[lexical.score encoder.score],
          'max_standardized_difference' => 2.0,
        },
      ],
      'calibration_valid_until' => '9999-12-31T23:59:59Z',
    }
  end

  def risk_control_data
    {
      'schema' => 'vangrail-risk-control-v1',
      'method' => 'learn_then_test_binomial',
      'block_at' => 0.8,
      'max_false_positive_rate' => 0.1,
      'confidence' => 0.95,
      'benign_cases' => 100,
      'false_positives' => 2,
      'false_positive_upper_bound' => 0.061_619_657_106_511_71,
      'calibration_manifest_sha256' => 'b' * 64,
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
end
