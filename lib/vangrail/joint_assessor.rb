# frozen_string_literal: true

require_relative 'joint_risk'
require_relative 'score'

module Vangrail
  # Runs score readers and feeds their validated outputs to one joint model.
  class JointAssessor
    attr_reader :readers, :model

    def initialize(readers:, model:)
      @readers = Array(readers).freeze
      @model = model
      raise ArgumentError, 'model must be a JointRiskModel' unless model.is_a?(JointRiskModel)

      ids = @readers.map { |reader| reader.id.to_s }
      raise ArgumentError, 'reader ids must be unique' unless ids.uniq == ids
      raise ArgumentError, 'too many readers' if ids.size > JointRiskArtifact::MAX_READERS
    end

    def assess(text, side:, origin:, language:, domain:, prior:, confidence: 0.95, **context)
      results = readers.map do |reader|
        score(reader, text, side: side, origin: origin, language: language,
                            domain: domain, **context)
      end
      model.estimate(
        results,
        side: side,
        origin: origin,
        language: language,
        domain: domain,
        prior: prior,
        confidence: confidence,
      )
    end

    private

    def score(reader, text, side:, **context)
      reader.score(text, side: side, **context)
    rescue StandardError => e
      ScoreResult.abstained(
        reader_id: reader.id,
        model_id: reader.model_id,
        feature_schema: reader.feature_schema,
        side: side,
        reason: "#{e.class}: #{e.message}",
      )
    end
  end
end
