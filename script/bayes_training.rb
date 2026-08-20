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

      strata.each do |labels, members|
        if members.size < role_cycle.size
          raise ArgumentError,
                "#{labels.join('/')} needs at least #{role_cycle.size} source groups to fill evaluation roles"
        end

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
      unless predictions.all? { |row| row[:role] == :threshold }
        raise ArgumentError, 'threshold selection requires threshold-role predictions'
      end

      predictions.select { |row| row[:label] == :benign }.map { |row| row.fetch(:score) }.max.ceil
    end

    def performance(predictions, threshold:)
      unless predictions.all? { |row| row[:role] == :test }
        raise ArgumentError, 'performance requires test-role predictions'
      end

      attacks = predictions.select { |row| row[:label] == :attack }
      benign = predictions.select { |row| row[:label] == :benign }
      {
        caught: attacks.count { |row| row.fetch(:score) > threshold },
        attacks: attacks.size,
        flagged: benign.count { |row| row.fetch(:score) > threshold },
        benign: benign.size,
      }
    end
  end
end
