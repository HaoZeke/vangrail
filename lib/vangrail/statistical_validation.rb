# frozen_string_literal: true

require 'digest'

module Vangrail
  # Structural, split, provenance, and artifact checks for evaluation inputs.
  module StatisticalValidation
    ROLES = %w[train calibration threshold test].freeze
    LABELS = %w[benign attack].freeze
    STATUSES = %w[ok error abstained].freeze
    REQUIRED_PREDICTION_FIELDS = %w[
      case_id parent_case_id group role label status score security_success
      utility_without_attack utility_under_attack secure_utility
    ].freeze
    THRESHOLD_SCHEMA = 'vangrail-threshold-provenance-v1'
    DIGEST = /\A[0-9a-f]{64}\z/
    BOOLEAN_VALUES = [true, false].freeze
    MAX_ARTIFACT_BYTES = 64 * 1024 * 1024

    private

    def validate_inputs!
      validate_predictions!
      validate_threshold!
      validate_artifacts!
    end

    def validate_predictions!
      unless predictions.is_a?(Array) && !predictions.empty? && predictions.all?(Hash)
        raise ArtifactError, 'predictions must be a nonempty array of objects'
      end

      predictions.each { |row| validate_prediction!(row) }
      unique_field!(predictions, 'case_id', 'one prediction per case')
      disjoint_roles!('group', 'group')
      disjoint_roles!('parent_case_id', 'generated variant parent')
      missing = ROLES - predictions.map { |row| row['role'] }.uniq
      raise ArtifactError, "prediction roles are missing #{missing.join(', ')}" unless missing.empty?
    end

    def validate_prediction!(row)
      missing = REQUIRED_PREDICTION_FIELDS - row.keys
      raise ArtifactError, "prediction is missing #{missing.join(', ')}" unless missing.empty?

      %w[case_id parent_case_id group].each do |field|
        raise ArtifactError, "prediction #{field} is required" if row[field].to_s.empty?
      end
      member!(row['role'], ROLES, 'prediction role')
      member!(row['label'], LABELS, 'prediction label')
      member!(row['status'], STATUSES, 'prediction status')
      validate_score!(row)
      %w[security_success utility_without_attack utility_under_attack secure_utility].each do |field|
        boolean!(row[field], "prediction #{field}")
      end
    end

    def validate_score!(row)
      score = row['score']
      if row['status'] == 'ok'
        probability!(score, 'successful prediction score')
      elsif !score.nil?
        probability!(score, 'prediction score')
      end
    end

    def unique_field!(rows, field, description)
      values = rows.map { |row| row[field] }
      return if values.uniq == values

      raise ArtifactError, "statistical verifier requires #{description}"
    end

    def disjoint_roles!(field, description)
      roles_by_value = predictions.group_by { |row| row[field] }
                                  .transform_values { |rows| rows.map { |row| row['role'] }.uniq }
      crossing = roles_by_value.select { |_value, roles| roles.size > 1 }.keys
      return if crossing.empty?

      raise ArtifactError, "#{description} appears in multiple roles: #{crossing.sort.join(', ')}"
    end

    def validate_threshold!
      validate_threshold_identity!
      validate_threshold_cases!
      validate_threshold_artifact!
      validate_interval!(threshold['interval'])
    end

    def validate_threshold_identity!
      raise ArtifactError, 'threshold provenance must be an object' unless threshold.is_a?(Hash)
      raise ArtifactError, "threshold schema must be #{THRESHOLD_SCHEMA}" unless threshold['schema'] == THRESHOLD_SCHEMA
      raise ArtifactError, 'threshold id is required' if threshold['id'].to_s.empty?

      probability!(threshold['value'], 'threshold value')
      return if threshold['selected_on'] == 'threshold'

      raise ArtifactError, 'threshold must be selected on the threshold split'
    end

    def validate_threshold_cases!
      selected = Array(threshold['case_ids'])
      unique_values!(selected, 'threshold case ids')
      expected = predictions.select { |row| row['role'] == 'threshold' }.map { |row| row['case_id'] }.sort
      raise ArtifactError, 'threshold case ids must equal the threshold split' unless selected.sort == expected
    end

    def validate_threshold_artifact!
      raise ArtifactError, 'threshold artifact id is required' if threshold['artifact_id'].to_s.empty?
      return if threshold['artifact_sha256'].to_s.match?(DIGEST)

      raise ArtifactError, 'threshold artifact SHA-256 is invalid'
    end

    def validate_interval!(interval)
      unless interval.is_a?(Hash) && !interval['method'].to_s.empty?
        raise ArtifactError, 'threshold interval method is required'
      end

      level = interval['level']
      return if level.is_a?(Numeric) && level.finite? && level.between?(0.0, 1.0) && ![0.0, 1.0].include?(level)

      raise ArtifactError, 'threshold interval level must be strictly between zero and one'
    end

    def validate_artifacts!
      unless artifacts.is_a?(Array) && !artifacts.empty? && artifacts.all?(Hash)
        raise ArtifactError, 'artifacts must be a nonempty array of objects'
      end

      unique_field!(artifacts, 'id', 'unique artifact ids')
      @verified_artifacts = artifacts.map { |artifact| validate_artifact!(artifact) }.sort_by { |row| row['id'] }
      selected = @verified_artifacts.detect { |artifact| artifact['id'] == threshold['artifact_id'] }
      return if selected && selected['sha256'] == threshold['artifact_sha256']

      raise ArtifactError, 'threshold provenance does not match a verified artifact'
    end

    def validate_artifact!(artifact)
      validate_artifact_identity!(artifact)
      size = validate_artifact_hash!(artifact)
      case_ids = validate_artifact_cases!(artifact)
      artifact_record(artifact, size, case_ids)
    rescue Errno::ENOENT, Errno::ENOTDIR => e
      raise ArtifactError, "artifact #{artifact['id']} is unavailable: #{e.message}"
    end

    def validate_artifact_identity!(artifact)
      %w[id path sha256 role case_ids].each do |field|
        raise ArtifactError, "artifact #{field} is required" unless artifact.key?(field)
      end
      member!(artifact['role'], ROLES - ['test'], 'artifact role')
      raise ArtifactError, "artifact #{artifact['id']} SHA-256 is invalid" unless artifact['sha256'].to_s.match?(DIGEST)
    end

    def validate_artifact_hash!(artifact)
      size = File.size(artifact['path'])
      raise ArtifactError, "artifact #{artifact['id']} exceeds #{MAX_ARTIFACT_BYTES} bytes" if size > MAX_ARTIFACT_BYTES

      actual = Digest::SHA256.file(artifact['path']).hexdigest
      raise ArtifactError, "artifact #{artifact['id']} hash does not match" unless actual == artifact['sha256']

      size
    end

    def validate_artifact_cases!(artifact)
      case_ids = Array(artifact['case_ids'])
      unique_values!(case_ids, "artifact #{artifact['id']} case ids")
      expected_role = case_ids.map { |id| prediction_by_id(id)&.fetch('role', nil) }.uniq
      raise ArtifactError, "artifact #{artifact['id']} case ids do not match its role" unless expected_role == [artifact['role']]

      case_ids
    end

    def artifact_record(artifact, size, case_ids)
      {
        'id' => artifact['id'],
        'sha256' => artifact['sha256'],
        'bytes' => size,
        'role' => artifact['role'],
        'case_ids' => case_ids.sort,
      }
    end

    def prediction_by_id(id)
      @prediction_index ||= predictions.to_h { |row| [row['case_id'], row] }
      @prediction_index[id]
    end

    def unique_values!(values, name)
      return if !values.empty? && values.all? { |value| !value.to_s.empty? } && values.uniq == values

      raise ArtifactError, "#{name} must be nonempty and unique"
    end

    def member!(value, allowed, name)
      return if allowed.include?(value)

      raise ArtifactError, "#{name} must be one of #{allowed.join(', ')}"
    end

    def boolean!(value, name)
      return if BOOLEAN_VALUES.include?(value)

      raise ArtifactError, "#{name} must be boolean"
    end

    def probability!(value, name)
      return if value.is_a?(Numeric) && value.finite? && value.between?(0.0, 1.0)

      raise ArtifactError, "#{name} must be a probability"
    end
  end
end
