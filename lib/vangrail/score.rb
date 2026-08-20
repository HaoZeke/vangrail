# frozen_string_literal: true

module Vangrail
  # Validated output from one risk reader.
  class ScoreResult
    STATUSES = %i[ok abstained invalid].freeze

    attr_reader :reader_id, :model_id, :feature_schema, :side, :scores,
                :status, :reason, :cost, :intervals, :metadata

    def initialize(reader_id:, model_id:, feature_schema:, side:, scores: {},
                   status: :ok, reason: nil, cost: {}, intervals: {}, metadata: {})
      @reader_id = reader_id.to_s.freeze
      @model_id = model_id.to_s.freeze
      @feature_schema = Array(feature_schema).map(&:to_s).uniq.freeze
      @side = side.to_sym
      @status = status.to_sym
      raise ArgumentError, "unknown score status #{status}" unless STATUSES.include?(@status)

      @scores = numeric_hash(scores)
      @cost = numeric_hash(cost)
      @intervals = interval_hash(intervals)
      @metadata = immutable(metadata)
      @reason = reason&.to_s&.freeze
      validate_ok!
      freeze
    end

    def self.ok(**options)
      new(status: :ok, **options)
    end

    def self.abstained(reason:, **options)
      new(status: :abstained, reason: reason, scores: {}, **options)
    end

    def self.invalid(reason:, **options)
      new(status: :invalid, reason: reason, scores: {}, **options)
    end

    def valid?
      status == :ok
    end

    def abstained?
      status == :abstained
    end

    def invalid?
      status == :invalid
    end

    def to_h
      {
        'reader_id' => reader_id,
        'model_id' => model_id,
        'feature_schema' => feature_schema,
        'side' => side.to_s,
        'status' => status.to_s,
        'scores' => scores,
        'intervals' => (intervals unless intervals.empty?),
        'cost' => (cost unless cost.empty?),
        'metadata' => (metadata unless metadata.empty?),
        'reason' => reason,
      }.compact
    end

    private

    def validate_ok!
      return unless valid?
      raise ArgumentError, 'an ok score needs a feature schema' if feature_schema.empty?
      return if scores.keys.sort == feature_schema.sort

      raise ArgumentError, 'score names do not match the feature schema'
    end

    def numeric_hash(values)
      raise ArgumentError, 'numeric fields must be a hash' unless values.is_a?(Hash)

      values.each_with_object({}) do |(name, value), normalized|
        raise ArgumentError, "#{name} must be a finite number" unless value.is_a?(Numeric) && value.finite?

        normalized[name.to_s.freeze] = value
      end.freeze
    end

    def interval_hash(values)
      raise ArgumentError, 'intervals must be a hash' unless values.is_a?(Hash)

      values.each_with_object({}) do |(name, bounds), normalized|
        low, high = Array(bounds)
        unless [low, high].all? { |value| value.is_a?(Numeric) && value.finite? } && low <= high
          raise ArgumentError, "#{name} must have finite ordered bounds"
        end

        normalized[name.to_s.freeze] = [low, high].freeze
      end.freeze
    end

    def immutable(value)
      case value
      when Hash
        value.each_with_object({}) do |(key, nested), copy|
          copy[key.to_s.freeze] = immutable(nested)
        end.freeze
      when Array then value.map { |nested| immutable(nested) }.freeze
      when String then value.dup.freeze
      else value.freeze
      end
    end
  end

  # Stable adapter around an optional local process, endpoint, or model runtime.
  class OptionalReader
    attr_reader :id, :model_id, :feature_schema, :provider

    def initialize(id:, model_id:, feature_schema:, provider: nil)
      @id = id.to_s.freeze
      @model_id = model_id.to_s.freeze
      @feature_schema = Array(feature_schema).map(&:to_s).freeze
      @provider = provider
    end

    def score(text, side:, **context)
      return missing(side) unless provider

      raw = if provider.respond_to?(:score)
              provider.score(text, side: side, **context)
            else
              provider.call(text, side: side, **context)
            end
      result = raw.is_a?(ScoreResult) ? raw : result_from(raw, side)
      identity_error(result, side) || result
    rescue StandardError => e
      ScoreResult.abstained(
        reader_id: id,
        model_id: model_id,
        feature_schema: feature_schema,
        side: side,
        reason: "#{e.class}: #{e.message}",
      )
    end

    private

    def missing(side)
      ScoreResult.abstained(
        reader_id: id,
        model_id: model_id,
        feature_schema: feature_schema,
        side: side,
        reason: "optional reader #{id} is not configured",
      )
    end

    def result_from(raw, side)
      raise ProtocolError, "reader #{id} returned #{raw.class}, expected a hash" unless raw.is_a?(Hash)

      ScoreResult.ok(
        reader_id: id,
        model_id: fetch(raw, :model_id),
        feature_schema: fetch(raw, :feature_schema),
        side: fetch(raw, :side) || side,
        scores: fetch(raw, :scores),
        cost: fetch(raw, :cost) || {},
        intervals: fetch(raw, :intervals) || {},
        metadata: fetch(raw, :metadata) || {},
      )
    end

    def identity_error(result, side)
      reason = if result.reader_id != id
                 "reader identity #{result.reader_id.inspect} does not match #{id.inspect}"
               elsif result.model_id != model_id
                 "model identity #{result.model_id.inspect} does not match #{model_id.inspect}"
               elsif result.feature_schema != feature_schema
                 'feature schema does not match the configured reader'
               elsif result.side != side.to_sym
                 "score side #{result.side} does not match #{side}"
               end
      return nil unless reason

      ScoreResult.invalid(
        reader_id: id,
        model_id: model_id,
        feature_schema: feature_schema,
        side: side,
        reason: reason,
      )
    end

    def fetch(hash, key)
      hash.key?(key) ? hash[key] : hash[key.to_s]
    end
  end
end
