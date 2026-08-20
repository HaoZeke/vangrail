# frozen_string_literal: true

require 'digest'

module Vangrail
  # Case-paired differences with deterministic percentile bootstrap intervals.
  module PairedStatistics
    private

    def paired_comparison(baseline, candidate, metrics)
      left = comparison_index(baseline, 'baseline')
      right = comparison_index(candidate, 'candidate')
      unless left.keys.sort == right.keys.sort
        raise ArtifactError, 'paired comparison case sets must match exactly'
      end

      ids = left.keys.sort
      names = Array(metrics).map(&:to_s).uniq.sort
      raise ArtifactError, 'paired comparison metrics are required' if names.empty?

      results = names.to_h do |metric|
        differences = ids.map { |id| paired_value(right[id], metric) - paired_value(left[id], metric) }
        lower, upper = bootstrap_interval(differences, metric)
        [metric, {
          'baseline' => ids.sum { |id| paired_value(left[id], metric) }.fdiv(ids.size),
          'candidate' => ids.sum { |id| paired_value(right[id], metric) }.fdiv(ids.size),
          'difference' => differences.sum.fdiv(ids.size),
          'lower' => lower,
          'upper' => upper,
        }]
      end
      {
        'paired_by' => 'case_id',
        'denominator' => ids.size,
        'interval' => {
          'method' => 'percentile_paired_bootstrap',
          'level' => 0.95,
          'seed' => bootstrap_seed,
          'replicates' => bootstrap_replicates,
        },
        'metrics' => results,
      }
    end

    def comparison_index(rows, name)
      normalized = stringify(rows)
      unless normalized.is_a?(Array) && !normalized.empty? && normalized.all?(Hash)
        raise ArtifactError, "#{name} comparison rows must be a nonempty array"
      end

      ids = normalized.map { |row| row['case_id'] }
      if ids.any? { |id| id.to_s.empty? } || ids.uniq != ids
        raise ArtifactError, "#{name} comparison needs unique case ids"
      end

      normalized.to_h { |row| [row['case_id'], row] }
    end

    def paired_value(row, metric)
      value = row[metric]
      unless value == true || value == false
        raise ArtifactError, "paired metric #{metric} must be boolean"
      end

      row['status'] == 'ok' && value ? 1.0 : 0.0
    end

    def bootstrap_interval(differences, metric)
      metric_seed = Digest::SHA256.hexdigest(metric)[0, 16].to_i(16) ^ bootstrap_seed
      random = Random.new(metric_seed)
      samples = Array.new(bootstrap_replicates) do
        differences.size.times.sum { differences.fetch(random.rand(differences.size)) }.fdiv(differences.size)
      end.sort
      alpha = 0.05
      lower_index = ((alpha / 2) * bootstrap_replicates).floor
      upper_index = (((1 - alpha / 2) * bootstrap_replicates).ceil - 1).clamp(0, bootstrap_replicates - 1)
      [samples.fetch(lower_index), samples.fetch(upper_index)]
    end
  end
end
