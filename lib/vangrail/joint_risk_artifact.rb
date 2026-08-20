# frozen_string_literal: true

require 'digest'
require 'json'
require_relative 'artifact_data'
require_relative 'errors'

module Vangrail
  # Bounded, versioned posterior approximation consumed by stdlib inference.
  class JointRiskArtifact
    include ArtifactData

    SCHEMA = 'vangrail-joint-risk-v1'
    METHODS = %w[laplace_diagonal].freeze
    MAX_BYTES = 4 * 1024 * 1024
    MAX_FEATURES = 256
    MAX_READERS = 64
    MAX_INTERACTIONS = 1024
    FIELDS = %w[
      schema id posterior_method training_prevalence normalization feature_schema readers intercept
      coefficients interactions context_offsets covariance_diagonal score_ranges
      supported calibration training_manifest_sha256
    ].freeze

    attr_reader :data, :sha256

    def initialize(raw, source_sha256: nil)
      raise ProtocolError, 'joint risk artifact must be a hash' unless raw.is_a?(Hash)

      @data = stringify(raw)
      validate!
      @data = immutable(@data)
      @sha256 = (source_sha256 || Digest::SHA256.hexdigest(canonical(@data))).freeze
      freeze
    end

    def self.load(path, expected_sha256: nil)
      size = File.size(path)
      raise ProtocolError, "joint risk artifact exceeds #{MAX_BYTES} bytes" if size > MAX_BYTES

      bytes = File.binread(path)
      actual = Digest::SHA256.hexdigest(bytes)
      raise ProtocolError, 'joint risk artifact hash does not match' if expected_sha256 && actual != expected_sha256

      new(JSON.parse(bytes), source_sha256: actual)
    rescue JSON::ParserError => e
      raise ProtocolError, "joint risk artifact is not JSON: #{e.message}"
    end

    def id
      data.fetch('id')
    end

    def posterior_method
      data.fetch('posterior_method')
    end

    def training_prevalence
      data.fetch('training_prevalence')
    end

    def feature_schema
      data.fetch('feature_schema')
    end

    def normalization
      data.fetch('normalization')
    end

    def readers
      data.fetch('readers')
    end

    def intercept
      data.fetch('intercept')
    end

    def coefficients
      data.fetch('coefficients')
    end

    def interactions
      data.fetch('interactions')
    end

    def context_offsets
      data.fetch('context_offsets')
    end

    def covariance_diagonal
      data.fetch('covariance_diagonal')
    end

    def score_ranges
      data.fetch('score_ranges')
    end

    def supported
      data.fetch('supported')
    end

    def calibration
      data.fetch('calibration')
    end

    def to_h
      data.merge('sha256' => sha256)
    end

    private

    def validate!
      unknown = data.keys - FIELDS
      raise ProtocolError, "unknown joint risk fields: #{unknown.join(', ')}" unless unknown.empty?
      raise ProtocolError, "unsupported joint risk schema #{data['schema'].inspect}" unless data['schema'] == SCHEMA
      raise ProtocolError, 'joint risk artifact id is required' if data['id'].to_s.empty?
      unless METHODS.include?(data['posterior_method'])
        raise ProtocolError, "unsupported posterior method #{data['posterior_method'].inspect}"
      end

      validate_prevalence!
      validate_normalization!
      validate_features!
      validate_readers!
      validate_parameters!
      validate_support!
      validate_provenance!
    end

    def validate_prevalence!
      value = data['training_prevalence']
      return if finite?(value) && value.positive? && value < 1

      raise ProtocolError, 'training_prevalence must be finite and strictly between 0 and 1'
    end

    def validate_normalization!
      value = data['normalization']
      return if value.is_a?(Hash) && !value['id'].to_s.empty?

      raise ProtocolError, 'normalization identity is required'
    end

    def validate_features!
      features = data['feature_schema']
      unless features.is_a?(Array) && features.size.between?(1, MAX_FEATURES) &&
             features.all? { |name| name.is_a?(String) && !name.empty? } && features.uniq == features
        raise ProtocolError, "feature_schema must contain 1..#{MAX_FEATURES} unique names"
      end
    end

    def validate_readers!
      specs = data['readers']
      unless specs.is_a?(Hash) && specs.size.between?(1, MAX_READERS)
        raise ProtocolError, "readers must contain 1..#{MAX_READERS} entries"
      end

      covered = specs.flat_map do |reader_id, spec|
        unless spec.is_a?(Hash) && !reader_id.empty? && !spec['model_id'].to_s.empty? &&
               spec['feature_schema'].is_a?(Array) && !spec['feature_schema'].empty?
          raise ProtocolError, "reader #{reader_id.inspect} has an invalid identity"
        end

        expected = spec['feature_schema'].map { |feature| "#{reader_id}.#{feature}" }
        unless (expected - feature_schema).empty?
          raise ProtocolError, "reader #{reader_id} names features outside feature_schema"
        end

        expected
      end
      return if covered.sort == feature_schema.sort

      raise ProtocolError, 'reader schemas must cover feature_schema exactly'
    end

    def validate_parameters!
      validate_finite!('intercept', data['intercept'])
      validate_numeric_table!('coefficients', data['coefficients'], allowed: feature_schema,
                                                                    exact: true)
      validate_interactions!
      allowed = ['intercept'] + feature_schema + interactions.keys
      validate_numeric_table!('covariance_diagonal', data['covariance_diagonal'], allowed: allowed,
                                                                                  nonnegative: true)
      validate_numeric_table!('context_offsets', data['context_offsets'])
      validate_ranges!
    end

    def validate_interactions!
      table = data['interactions']
      unless table.is_a?(Hash) && table.size <= MAX_INTERACTIONS
        raise ProtocolError, "interactions must be a hash with at most #{MAX_INTERACTIONS} entries"
      end

      table.each do |name, value|
        parts = name.split('*', -1)
        unless parts.size == 2 && parts.all? { |feature| feature_schema.include?(feature) }
          raise ProtocolError, "interaction #{name.inspect} names an unknown feature"
        end

        validate_finite!("interaction #{name}", value)
      end
    end

    def validate_ranges!
      ranges = data['score_ranges']
      unless ranges.is_a?(Hash) && ranges.keys.sort == feature_schema.sort
        raise ProtocolError, 'score_ranges must name every feature exactly once'
      end

      ranges.each do |name, bounds|
        low, high = Array(bounds)
        unless finite?(low) && finite?(high) && low <= high
          raise ProtocolError, "score range #{name} must have finite ordered bounds"
        end
      end
    end

    def validate_support!
      support = data['supported']
      required = %w[sides origins languages domains]
      unless support.is_a?(Hash) && (support.keys - required).empty? &&
             required.all? { |name| support[name].is_a?(Array) && !support[name].empty? }
        raise ProtocolError, 'supported must name nonempty sides, origins, languages, and domains'
      end

      calibration = data['calibration']
      unless calibration.is_a?(Hash) && !calibration['id'].to_s.empty? &&
             !calibration['method'].to_s.empty?
        raise ProtocolError, 'calibration identity and method are required'
      end
      validate_calibration!(calibration)
    end

    def validate_calibration!(calibration)
      return if calibration['method'] == 'identity'
      raise ProtocolError, "unknown calibration method #{calibration['method'].inspect}" unless calibration['method'] == 'platt'

      validate_finite!('calibration intercept', calibration['intercept'])
      validate_finite!('calibration slope', calibration['slope'])
      raise ProtocolError, 'calibration slope must be positive' unless calibration['slope'].positive?

      covariance = calibration['covariance_diagonal']
      validate_numeric_table!('calibration covariance', covariance,
                               allowed: %w[intercept slope], exact: true, nonnegative: true)
    end

    def validate_provenance!
      digest = data['training_manifest_sha256'].to_s
      return if digest.match?(/\A[0-9a-f]{64}\z/)

      raise ProtocolError, 'training_manifest_sha256 must be a lowercase SHA-256 digest'
    end

    def validate_numeric_table!(name, table, allowed: nil, exact: false, nonnegative: false)
      raise ProtocolError, "#{name} must be a hash" unless table.is_a?(Hash)
      raise ProtocolError, "#{name} names an unknown parameter" if allowed && !(table.keys - allowed).empty?
      raise ProtocolError, "#{name} must name every parameter" if exact && table.keys.sort != allowed.sort

      table.each do |key, value|
        validate_finite!("#{name} #{key}", value)
        raise ProtocolError, "#{name} #{key} must be nonnegative" if nonnegative && value.negative?
      end
    end

    def validate_finite!(name, value)
      raise ProtocolError, "#{name} must be finite" unless finite?(value)
    end

    def finite?(value)
      value.is_a?(Numeric) && value.finite?
    end
  end
end
