# frozen_string_literal: true

require_relative 'helper'
require_relative 'support/joint_risk_fixture'

class TestJointRiskOod < Minitest::Test
  include JointRiskFixture

  def test_distance_and_reader_disagreement_abstain
    model = Vangrail::JointRiskModel.new(Vangrail::JointRiskArtifact.new(artifact_data))

    distant = estimate(model, lexical: 3.0, encoder: 3.0)
    disagreement = estimate(model, lexical: -1.0, encoder: 2.0)

    assert_predicate distant, :abstained?
    assert_match(/score-vector distance/, distant.reason)
    assert_predicate disagreement, :abstained?
    assert_match(/reader disagreement/, disagreement.reason)
  end

  def test_expired_calibration_abstains
    expired = artifact_data.fetch('ood').merge('calibration_valid_until' => '2000-01-01T00:00:00Z')
    model = Vangrail::JointRiskModel.new(
      Vangrail::JointRiskArtifact.new(artifact_data.merge('ood' => expired)),
      clock: -> { Time.utc(2001, 1, 1) },
    )

    result = estimate(model, lexical: 0.5, encoder: 1.0)

    assert_predicate result, :abstained?
    assert_match(/calibration expired/, result.reason)
  end

  def test_artifact_rejects_invalid_ood_parameters
    invalid_scale = artifact_data.fetch('ood').merge(
      'feature_scales' => { 'lexical.score' => 0.0, 'encoder.score' => 1.0 },
    )
    invalid_expiry = artifact_data.fetch('ood').merge('calibration_valid_until' => 'not-a-time')

    assert_raises(Vangrail::ProtocolError) do
      Vangrail::JointRiskArtifact.new(artifact_data.merge('ood' => invalid_scale))
    end
    assert_raises(Vangrail::ProtocolError) do
      Vangrail::JointRiskArtifact.new(artifact_data.merge('ood' => invalid_expiry))
    end
  end

  private

  def estimate(model, lexical:, encoder:)
    model.estimate(
      [score(:lexical, 'lexical-v1', lexical), score(:encoder, 'encoder-v1', encoder)],
      side: :context,
      origin: :data,
      language: :en,
      domain: :handbook,
      prior: 0.5,
    )
  end
end
