# frozen_string_literal: true

require_relative 'helper'
require_relative '../script/bayes_training'

class TestBayesTraining < Minitest::Test
  def test_a_source_group_has_exactly_one_evaluation_role
    cases = [
      { id: 'attack-a-plain', label: :attack, group: 'attack-a', text: 'plain' },
      { id: 'attack-a-encoded', label: :attack, group: 'attack-a', text: 'encoded' },
      { id: 'attack-b', label: :attack, group: 'attack-b', text: 'b' },
      { id: 'attack-c', label: :attack, group: 'attack-c', text: 'c' },
      { id: 'attack-d', label: :attack, group: 'attack-d', text: 'd' },
      { id: 'benign-a', label: :benign, group: 'benign-a', text: 'a' },
      { id: 'benign-b', label: :benign, group: 'benign-b', text: 'b' },
      { id: 'benign-c', label: :benign, group: 'benign-c', text: 'c' },
      { id: 'benign-d', label: :benign, group: 'benign-d', text: 'd' },
    ]

    roles = Vangrail::BayesTraining.grouped_partition(cases, seed: 'paper-v1')
    assigned = roles.filter_map { |role, rows| role if rows.any? { |row| row[:group] == 'attack-a' } }

    assert_equal 1, assigned.size
    assert_equal 2, roles.fetch(assigned.first).count { |row| row[:group] == 'attack-a' }
  end

  def test_each_label_stratum_uses_the_declared_role_weights
    cases = %i[attack benign].flat_map do |label|
      8.times.map do |index|
        { id: "#{label}-#{index}", label: label, group: "#{label}-#{index}", text: index.to_s }
      end
    end

    roles = Vangrail::BayesTraining.grouped_partition(cases, seed: 'paper-v1')
    expected = { train: 5, calibration: 1, threshold: 1, test: 1 }

    %i[attack benign].each do |label|
      actual = roles.transform_values { |rows| rows.count { |row| row[:label] == label } }

      assert_equal expected, actual
    end
  end

  def test_each_case_in_a_role_receives_one_prediction
    cases = %i[attack benign].flat_map do |label|
      8.times.map do |index|
        { id: "#{label}-#{index}", label: label, group: "#{label}-#{index}", text: index.to_s }
      end
    end
    roles = Vangrail::BayesTraining.grouped_partition(cases, seed: 'paper-v1')
    called = []

    predictions = Vangrail::BayesTraining.predict(roles, role: :test) do |row|
      called << row[:id]
      row[:text].to_f
    end

    expected_ids = roles.fetch(:test).map { |row| row[:id] }
    assert_equal expected_ids, called
    assert_equal called.uniq, called
    assert predictions.all? { |row| row[:role] == :test }
  end

  def test_threshold_selection_rejects_predictions_from_another_role
    predictions = [{ id: 'calibration-a', label: :benign, role: :calibration, score: 3.0 }]

    error = assert_raises(ArgumentError) do
      Vangrail::BayesTraining.select_threshold(predictions)
    end

    assert_match(/threshold/, error.message)
  end

  def test_threshold_comes_only_from_threshold_role_benign_scores
    predictions = [
      { id: 'benign-a', label: :benign, role: :threshold, score: 1.2 },
      { id: 'benign-b', label: :benign, role: :threshold, score: 3.1 },
      { id: 'attack-a', label: :attack, role: :threshold, score: 100.0 },
    ]

    assert_equal 4, Vangrail::BayesTraining.select_threshold(predictions)
  end
end
