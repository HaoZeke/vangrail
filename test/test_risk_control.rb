# frozen_string_literal: true

require_relative 'helper'

class TestRiskControl < Minitest::Test
  MANIFEST = 'b' * 64

  def predictions(role: :threshold, benign: 20)
    benign_rows = Array.new(benign) do |index|
      { id: "benign-#{index}", role: role, label: :benign, posterior: (index + 1) / 100.0 }
    end
    attack_rows = Array.new(10) do |index|
      { id: "attack-#{index}", role: role, label: :attack, posterior: 0.5 + (index / 100.0) }
    end
    benign_rows + attack_rows
  end

  def test_learn_then_test_selects_a_certified_block_threshold
    control = Vangrail::RiskControl.fit(
      predictions,
      max_false_positive_rate: 0.25,
      confidence: 0.95,
      calibration_manifest_sha256: MANIFEST,
    )
    policy = control.policy(review_at: 0.05)

    assert_equal 'learn_then_test_binomial', control.method
    assert_operator control.false_positive_upper_bound, :<=, 0.25
    assert_equal :allow, policy.action_for(0.01)
    assert_equal :review, policy.action_for(0.1)
    assert_equal :block, policy.action_for(0.8)
    assert_equal MANIFEST, control.calibration_manifest_sha256
    assert_predicate control, :frozen?
  end

  def test_threshold_fitting_rejects_other_roles_and_unprovable_targets
    assert_raises(ArgumentError) do
      Vangrail::RiskControl.fit(
        predictions(role: :calibration),
        max_false_positive_rate: 0.25,
        confidence: 0.95,
        calibration_manifest_sha256: MANIFEST,
      )
    end
    error = assert_raises(Vangrail::ProtocolError) do
      Vangrail::RiskControl.fit(
        predictions(benign: 1),
        max_false_positive_rate: 0.01,
        confidence: 0.95,
        calibration_manifest_sha256: MANIFEST,
      )
    end

    assert_match(/cannot certify/, error.message)
  end

  def test_risk_control_rejects_tampered_artifacts
    control = Vangrail::RiskControl.fit(
      predictions,
      max_false_positive_rate: 0.25,
      confidence: 0.95,
      calibration_manifest_sha256: MANIFEST,
    )
    tampered = control.to_h.merge('false_positive_upper_bound' => 0.9)

    assert_raises(Vangrail::ProtocolError) { Vangrail::RiskControl.new(tampered) }
  end
end
