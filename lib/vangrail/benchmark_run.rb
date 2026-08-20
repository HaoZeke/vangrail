# frozen_string_literal: true

require_relative 'artifact_data'
require_relative 'errors'

module Vangrail
  # Immutable per-case benchmark results with explicit denominator accounting.
  class BenchmarkRun
    include ArtifactData

    SCHEMA = 'vangrail-benchmark-run-v1'
    STATUSES = %w[ok error abstained].freeze
    FIELDS = %w[
      schema adapter benchmark target attack seed source cases status_counts denominator
    ].freeze

    attr_reader :data

    def initialize(raw)
      raise ArtifactError, 'benchmark run must be a hash' unless raw.is_a?(Hash)

      @data = stringify(raw)
      validate!
      @data = immutable(@data)
      freeze
    end

    def to_h
      data
    end

    private

    def validate!
      unknown = data.keys - FIELDS
      raise ArtifactError, "unknown benchmark run fields: #{unknown.join(', ')}" unless unknown.empty?
      raise ArtifactError, "unsupported benchmark schema #{data['schema'].inspect}" unless data['schema'] == SCHEMA

      %w[adapter benchmark target attack source].each { |name| require_hash!(name) }
      raise ArtifactError, 'benchmark seed must be an integer' unless data['seed'].is_a?(Integer)

      validate_cases!
      validate_counts!
    end

    def require_hash!(name)
      value = data[name]
      return if value.is_a?(Hash) && !value.empty?

      raise ArtifactError, "benchmark #{name} must be a nonempty hash"
    end

    def validate_cases!
      cases = data['cases']
      unless cases.is_a?(Array) && !cases.empty? && cases.all?(Hash)
        raise ArtifactError, 'benchmark cases must be a nonempty array of hashes'
      end

      ids = cases.map { |row| row['case_id'] }
      invalid_id = ids.any? { |id| id.to_s.empty? }
      raise ArtifactError, 'every benchmark case needs a unique case_id' if invalid_id || ids.uniq != ids

      statuses = cases.map { |row| row['status'] }
      unknown = statuses - STATUSES
      raise ArtifactError, "unknown benchmark statuses: #{unknown.uniq.join(', ')}" unless unknown.empty?
    end

    def validate_counts!
      unless data['denominator'] == data['cases'].size
        raise ArtifactError, 'benchmark denominator must equal the number of cases'
      end

      expected = STATUSES.to_h { |status| [status, data['cases'].count { |row| row['status'] == status }] }
      return if data['status_counts'] == expected

      raise ArtifactError, 'benchmark status_counts do not match the per-case records'
    end
  end
end
