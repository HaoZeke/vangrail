# frozen_string_literal: true

require 'digest'

module Vangrail
  # Dataset splitting and evaluation support for the generated Bayes artifact.
  # This module belongs to the development scripts rather than the gem runtime.
  module BayesTraining
    ROLES = %i[train calibration threshold test].freeze

    module_function

    def grouped_partition(cases, seed:)
      partitions = ROLES.to_h { |role| [role, []] }
      groups = cases.group_by { |row| row.fetch(:group) }
      ordered = groups.sort_by do |group, _rows|
        Digest::SHA256.hexdigest("#{seed}\0#{group}")
      end

      ordered.each_with_index do |(_group, rows), index|
        partitions.fetch(ROLES[index % ROLES.size]).concat(rows)
      end
      partitions
    end
  end
end
