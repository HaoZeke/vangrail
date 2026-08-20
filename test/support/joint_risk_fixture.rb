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
      'threat_model' => {
        'training_composition' => { 'override' => 0.5, 'exfiltration' => 0.5 },
        'log_likelihood_offsets' => { 'override' => Math.log(2.0), 'exfiltration' => Math.log(0.5) },
        'covariance_diagonal' => { 'override' => 0.01, 'exfiltration' => 0.01 },
      },
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
end
