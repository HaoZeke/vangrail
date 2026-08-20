# frozen_string_literal: true

require 'digest'
require 'json'
require_relative 'artifact_data'
require_relative 'errors'

module Vangrail
  # Versioned adaptive cases with explicit access, budget, and utility constraints.
  class AdaptiveAttackMatrix
    include ArtifactData

    SCHEMA = 'vangrail-adaptive-attack-matrix-v1'
    FAMILIES = %w[
      obfuscation encoding multilingual role_impersonation paraphrase score_query binary_query
      black_box_search reinforcement_learning white_box argument_steering conditional_dummy
      long_horizon cross_tool memory_poisoning policy_laundering grant_replay use_exhaustion
      retry_exploitation sink_exfiltration human_red_team
    ].freeze
    ACCESS = %w[black_box score_query binary_query white_box human].freeze
    SPLITS = %w[train calibration threshold test].freeze
    FIELDS = %w[schema id version cases].freeze
    CASE_FIELDS = %w[
      id parent_case_id family split language domain origin access attack_budget seed
      utility_constraint scenario
    ].freeze
    MAX_CASES = 100_000
    MAX_BYTES = 16 * 1024 * 1024

    attr_reader :data, :sha256

    def initialize(raw = nil, source_sha256: nil, **fields)
      raw = fields if raw.nil?
      raise ArtifactError, 'adaptive attack matrix fields are ambiguous' unless fields.empty? || raw.equal?(fields)
      raise ArtifactError, 'adaptive attack matrix must be a hash' unless raw.is_a?(Hash)

      @data = stringify(raw)
      validate!
      encoded = canonical(@data)
      raise ArtifactError, "adaptive attack matrix exceeds #{MAX_BYTES} bytes" if encoded.bytesize > MAX_BYTES

      @sha256 = (source_sha256 || Digest::SHA256.hexdigest(encoded)).freeze
      @data = immutable(@data)
      freeze
    end

    def self.load(path, expected_sha256: nil)
      size = File.size(path)
      raise ArtifactError, "adaptive attack matrix exceeds #{MAX_BYTES} bytes" if size > MAX_BYTES

      bytes = File.binread(path)
      actual = Digest::SHA256.hexdigest(bytes)
      raise ArtifactError, 'adaptive attack matrix hash does not match' if expected_sha256 && actual != expected_sha256

      new(JSON.parse(bytes), source_sha256: actual)
    rescue JSON::ParserError => e
      raise ArtifactError, "adaptive attack matrix is not JSON: #{e.message}"
    end

    def to_h
      data
    end

    def id
      data['id']
    end

    def version
      data['version']
    end

    private

    def validate!
      unknown = data.keys - FIELDS
      raise ArtifactError, "unknown adaptive matrix fields: #{unknown.join(', ')}" unless unknown.empty?
      raise ArtifactError, "adaptive matrix schema must be #{SCHEMA}" unless data['schema'] == SCHEMA

      %w[id version].each { |field| required_string!(data[field], "matrix #{field}") }
      cases = data['cases']
      unless cases.is_a?(Array) && cases.size.between?(1, MAX_CASES) && cases.all?(Hash)
        raise ArtifactError, "adaptive matrix cases must contain 1..#{MAX_CASES} objects"
      end

      cases.each { |row| validate_case!(row) }
      ids = cases.map { |row| row['id'] }
      raise ArtifactError, 'adaptive matrix case ids must be unique' unless ids.uniq == ids
    end

    def validate_case!(row)
      unknown = row.keys - CASE_FIELDS
      raise ArtifactError, "unknown adaptive case fields: #{unknown.join(', ')}" unless unknown.empty?

      %w[id parent_case_id language domain origin].each do |field|
        required_string!(row[field], "adaptive case #{field}")
      end
      member!(row, 'family', FAMILIES)
      member!(row, 'split', SPLITS)
      member!(row, 'access', ACCESS)
      positive_integer!(row['attack_budget'], 'adaptive case attack_budget')
      integer!(row['seed'], 'adaptive case seed')
      required_hash!(row['utility_constraint'], 'adaptive case utility_constraint')
      required_hash!(row['scenario'], 'adaptive case scenario')
    end

    def member!(row, field, allowed)
      return if allowed.include?(row[field])

      raise ArtifactError, "adaptive case #{field} must be one of #{allowed.join(', ')}"
    end

    def required_string!(value, name)
      return if value.is_a?(String) && !value.empty?

      raise ArtifactError, "#{name} is required"
    end

    def required_hash!(value, name)
      return if value.is_a?(Hash) && !value.empty?

      raise ArtifactError, "#{name} must be a nonempty object"
    end

    def integer!(value, name)
      return if value.is_a?(Integer)

      raise ArtifactError, "#{name} must be an integer"
    end

    def positive_integer!(value, name)
      integer!(value, name)
      raise ArtifactError, "#{name} must be positive" unless value.positive?
    end
  end
end
