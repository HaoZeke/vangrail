# frozen_string_literal: true

require 'digest'

module Vangrail
  # Dataset splitting and evaluation support for the generated Bayes artifact.
  # This module belongs to the development scripts rather than the gem runtime.
  module BayesTraining
    ROLE_WEIGHTS = { train: 5, calibration: 1, threshold: 1, test: 1 }.freeze
    ROLES = ROLE_WEIGHTS.keys.freeze

    module_function

    def grouped_partition(cases, seed:)
      partitions = ROLES.to_h { |role| [role, []] }
      groups = cases.group_by { |row| row.fetch(:group) }
      strata = groups.group_by do |_group, rows|
        rows.map { |row| row.fetch(:label) }.uniq.sort_by(&:to_s)
      end
      role_cycle = ROLE_WEIGHTS.flat_map { |role, weight| [role] * weight }

      strata.each_value do |members|
        ordered = members.sort_by do |group, _rows|
          Digest::SHA256.hexdigest("#{seed}\0#{group}")
        end
        ordered.each_with_index do |(_group, rows), index|
          partitions.fetch(role_cycle[index % role_cycle.size]).concat(rows)
        end
      end
      partitions
    end

    def predict(partitions, role:)
      partitions.fetch(role).map do |row|
        row.merge(role: role, score: yield(row))
      end
    end

    def select_threshold(predictions)
      return if predictions.all? { |row| row[:role] == :threshold }

      raise ArgumentError, 'threshold selection requires threshold-role predictions'
    end
  end
end
