# frozen_string_literal: true

require 'digest'
require_relative 'joint_risk_training_data'
require_relative 'joint_risk_training_ood'

module Vangrail
  # Orchestrates disjoint joint-model fitting without mixing role ownership.
  class JointRiskTrainingPipeline
    attr_reader :cases, :id, :readers, :normalization, :calibration_valid_until,
                :max_false_positive_rate, :interactions, :disagreement_pairs,
                :risk_confidence, :iterations, :ridge

    def initialize(cases, id:, readers:, normalization:, calibration_valid_until:,
                   max_false_positive_rate:, interactions: [], disagreement_pairs: [],
                   risk_confidence: 0.95, iterations: 100, ridge: 4.0)
      @cases = cases
      @id = id
      @readers = readers
      @normalization = normalization
      @calibration_valid_until = calibration_valid_until
      @max_false_positive_rate = max_false_positive_rate
      @interactions = interactions
      @disagreement_pairs = disagreement_pairs
      @risk_confidence = risk_confidence
      @iterations = iterations
      @ridge = ridge
    end

    def fit
      prepare_roles
      fit_posterior
      fit_calibration_layers
      artifact = build_artifact
      [artifact, JointRiskTraining.report(@rows, @test, artifact, @interaction_names,
                                         @context_terms, @parameters)]
    end

    private

    def prepare_roles
      @rows, @feature_schema, @reader_specs = JointRiskTraining.prepare(cases, readers)
      JointRiskTraining.validate!(@rows, @feature_schema)
      @interaction_names = JointRiskTraining.normalize_interactions(interactions, @feature_schema)
      @disagreement_names = JointRiskTrainingOod.normalize_pairs(disagreement_pairs, @feature_schema)
      @train = role(:train)
      @calibration = role(:calibration)
      @threshold = role(:threshold)
      @test = role(:test)
      @context_terms = JointRiskTraining.context_terms(@train)
      @terms = ['intercept'] + @feature_schema + @interaction_names + @context_terms.values.flatten
    end

    def fit_posterior
      @parameters, @covariance = JointRiskTraining.fit_logistic(
        @train,
        @terms,
        @interaction_names,
        @context_terms,
        iterations,
        ridge,
      )
      @threat_model = JointRiskTraining.fit_threat_model(
        @train,
        @parameters,
        @interaction_names,
        @context_terms,
      )
      @ood = JointRiskTrainingOod.fit(
        @train,
        @calibration,
        @feature_schema,
        @disagreement_names,
        calibration_valid_until,
        epsilon: JointRiskTraining::EPSILON,
      )
    end

    def fit_calibration_layers
      @calibration_data = JointRiskTraining.fit_calibration(
        @calibration,
        @parameters,
        @interaction_names,
        @context_terms,
        iterations,
        ridge,
      )
      predictions = JointRiskTraining.predictions(
        @threshold,
        @calibration_data,
        @interaction_names,
        @context_terms,
        @parameters,
      )
      @risk_control = RiskControl.fit(
        predictions,
        max_false_positive_rate: max_false_positive_rate,
        confidence: risk_confidence,
        calibration_manifest_sha256: threshold_manifest,
      )
      @prevalence = @train.count { |row| row[:label] == :attack }.fdiv(@train.size)
    end

    def build_artifact
      JointRiskArtifact.new(
        JointRiskTraining.artifact_hash(
          id: id,
          train: @train,
          calibration: @calibration,
          threshold: @threshold,
          features: @feature_schema,
          readers: @reader_specs,
          normalization: normalization,
          interactions: @interaction_names,
          contexts: @context_terms,
          parameters: @parameters,
          covariance: @covariance,
          threat_model: @threat_model,
          ood: @ood,
          risk_control: @risk_control,
          calibration_data: @calibration_data,
          prevalence: @prevalence,
        ),
      )
    end

    def threshold_manifest
      Digest::SHA256.hexdigest(JointRiskTrainingData.canonical(@threshold))
    end

    def role(name)
      @rows.select { |row| row[:role] == name }
    end
  end
end
