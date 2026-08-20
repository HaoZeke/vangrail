# frozen_string_literal: true

module Vangrail
  # Stable Markdown rendering for the metrics recomputed by StatisticalVerifier.
  module StatisticalReportTable
    module_function

    def render(report)
      attack_n = report.dig('roles', 'test', 'labels', 'attack')
      benign_n = report.dig('roles', 'test', 'labels', 'benign')
      test_n = report.dig('roles', 'test', 'denominator')
      rows = [
        ['security success', report.dig('outcomes', 'security_success'), attack_n],
        ['attack success', report.dig('outcomes', 'attack_success'), attack_n],
        ['benign utility', report.dig('outcomes', 'benign_utility'), benign_n],
        ['utility under attack', report.dig('outcomes', 'utility_under_attack'), attack_n],
        ['secure utility', report.dig('outcomes', 'secure_utility'), attack_n],
        ['true-positive rate', report.dig('detection', 'true_positive_rate'), attack_n],
        ['false-positive rate', report.dig('detection', 'false_positive_rate'), benign_n],
        ['ROC area', report.dig('curves', 'roc', 'area'), test_n],
        ['average precision', report.dig('curves', 'precision_recall', 'average_precision'), test_n],
        ['partial ROC area (FPR <= 0.1)', report.dig('curves', 'partial_auc', 'area'), test_n],
        ['Brier score', report.dig('calibration', 'brier_score'), test_n],
        ['negative log score', report.dig('calibration', 'negative_log_score'), test_n],
        ['expected calibration error', report.dig('calibration', 'expected_calibration_error'), test_n],
        ['retained coverage', report.dig('selective', 'retained_coverage'), test_n],
        ['selective classification risk', report.dig('selective', 'classification_risk'),
         report.dig('selective', 'retained')],
      ]
      lines = [
        '| metric | estimate | denominator |',
        '|---|---:|---:|',
      ]
      rows.each { |name, value, denominator| lines << "| #{name} | #{format_value(value)} | #{denominator} |" }
      lines.join("\n") << "\n"
    end

    def format_value(value)
      value.nil? ? 'NA' : format('%.6f', value)
    end
  end
end
