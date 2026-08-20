# frozen_string_literal: true

module Vangrail
  # Read-only public fields of a validated joint-risk artifact.
  module JointRiskArtifactAccessors
    def id = data.fetch('id')
    def posterior_method = data.fetch('posterior_method')
    def training_prevalence = data.fetch('training_prevalence')
    def feature_schema = data.fetch('feature_schema')
    def normalization = data.fetch('normalization')
    def readers = data.fetch('readers')
    def intercept = data.fetch('intercept')
    def coefficients = data.fetch('coefficients')
    def interactions = data.fetch('interactions')
    def context_offsets = data.fetch('context_offsets')
    def covariance_diagonal = data.fetch('covariance_diagonal')
    def threat_model = data.fetch('threat_model')
    def ood = data.fetch('ood')
    def risk_control = data.fetch('risk_control')
    def score_ranges = data.fetch('score_ranges')
    def supported = data.fetch('supported')
    def calibration = data.fetch('calibration')
  end
end
