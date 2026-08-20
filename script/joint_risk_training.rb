# frozen_string_literal: true

require 'digest'
require 'json'
require_relative '../lib/vangrail/joint_risk_artifact'

module Vangrail
  # Deterministic grouped training for the compact Laplace joint-risk artifact.
  module JointRiskTraining
    ROLES = %i[train calibration test].freeze
    CONTEXTS = %i[side origin language domain].freeze
    EPSILON = 1e-12

    module_function

    def fit(cases, id:, readers:, normalization:, interactions: [], iterations: 100, l2: 4.0)
      rows, feature_schema, reader_specs = prepare(cases, readers)
      validate!(rows, feature_schema)
      interaction_names = normalize_interactions(interactions, feature_schema)
      train = rows.select { |row| row[:role] == :train }
      calibration = rows.select { |row| row[:role] == :calibration }
      test = rows.select { |row| row[:role] == :test }
      context_terms = context_terms(train)
      terms = ['intercept'] + feature_schema + interaction_names + context_terms.values.flatten
      parameters, covariance = fit_logistic(train, terms, interaction_names,
                                            context_terms, iterations, l2)
      calibration_data = fit_calibration(calibration, parameters, interaction_names,
                                         context_terms, iterations, l2)
      prevalence = train.count { |row| row[:label] == :attack }.fdiv(train.size)
      artifact = JointRiskArtifact.new(
        artifact_hash(id, rows, train, calibration, feature_schema, reader_specs,
                      normalization, interaction_names, context_terms, parameters,
                      covariance, calibration_data, prevalence),
      )
      [artifact, report(rows, test, artifact, interaction_names, context_terms, parameters)]
    end

    def prepare(cases, readers)
      reader_specs = stringify(readers)
      feature_schema = reader_specs.flat_map do |reader_id, spec|
        Array(spec['feature_schema']).map { |feature| "#{reader_id}.#{feature}" }
      end
      rows = Array(cases).map { |row| normalize_row(row) }.sort_by { |row| row[:id] }
      [rows, feature_schema, reader_specs]
    end

    def normalize_row(raw)
      row = raw.transform_keys(&:to_sym)
      {
        id: row.fetch(:id).to_s,
        group: row.fetch(:group).to_s,
        role: row.fetch(:role).to_sym,
        label: row.fetch(:label).to_sym,
        scores: row.fetch(:scores).to_h { |name, value| [name.to_s, value] }.freeze,
        side: row.fetch(:side).to_s,
        origin: row.fetch(:origin).to_s,
        language: row.fetch(:language).to_s,
        domain: row.fetch(:domain).to_s,
      }.freeze
    end

    def validate!(rows, feature_schema)
      raise ArgumentError, 'joint training needs cases' if rows.empty?
      raise ArgumentError, 'case ids must be unique' unless rows.map { |row| row[:id] }.uniq.size == rows.size

      rows.each do |row|
        raise ArgumentError, "unknown role #{row[:role]}" unless ROLES.include?(row[:role])
        raise ArgumentError, "unknown label #{row[:label]}" unless %i[attack benign].include?(row[:label])
        unless row[:scores].keys.sort == feature_schema.sort && row[:scores].values.all? { |value| finite?(value) }
          raise ArgumentError, "case #{row[:id]} has an invalid score schema"
        end
      end
      ROLES.each do |role|
        role_rows = rows.select { |row| row[:role] == role }
        raise ArgumentError, "role #{role} is empty" if role_rows.empty?
        raise ArgumentError, "role #{role} needs both labels" unless role_rows.map { |row| row[:label] }.uniq.size == 2
      end
      roles_by_group = rows.group_by { |row| row[:group] }
                           .transform_values { |members| members.map { |row| row[:role] }.uniq }
      overlap = roles_by_group.detect { |_group, roles| roles.size > 1 }
      raise ArgumentError, "group #{overlap.first} crosses roles" if overlap
    end

    def normalize_interactions(interactions, feature_schema)
      Array(interactions).map do |pair|
        left, right = Array(pair).map(&:to_s)
        unless left && right && feature_schema.include?(left) && feature_schema.include?(right)
          raise ArgumentError, "invalid interaction #{pair.inspect}"
        end

        "#{left}*#{right}"
      end.uniq.sort.freeze
    end

    def context_terms(train)
      CONTEXTS.to_h do |context|
        values = train.map { |row| row.fetch(context) }.uniq.sort
        [context, values.drop(1).map { |value| "#{context}:#{value}" }.freeze]
      end.freeze
    end

    def fit_logistic(rows, terms, interactions, contexts, iterations, l2)
      prevalence = rows.count { |row| row[:label] == :attack }.fdiv(rows.size)
      parameters = terms.to_h { |term| [term, term == 'intercept' ? logit(prevalence) : 0.0] }
      iterations.times do
        gradient, curvature = derivatives(rows, terms, interactions, contexts, parameters, l2)
        largest = 0.0
        terms.each do |term|
          step = 0.5 * gradient.fetch(term) / [curvature.fetch(term), EPSILON].max
          parameters[term] += step
          largest = [largest, step.abs].max
        end
        break if largest < 1e-9
      end
      _, curvature = derivatives(rows, terms, interactions, contexts, parameters, l2)
      covariance = curvature.transform_values { |value| 1.0 / [value, EPSILON].max }
      [parameters.freeze, covariance.freeze]
    end

    def derivatives(rows, terms, interactions, contexts, parameters, l2)
      gradient = terms.to_h { |term| [term, term == 'intercept' ? 0.0 : -l2 * parameters.fetch(term)] }
      curvature = terms.to_h { |term| [term, term == 'intercept' ? 0.0 : l2] }
      rows.each do |row|
        vector = design(row, interactions, contexts)
        probability = logistic(dot(parameters, vector))
        error = label(row) - probability
        weight = probability * (1 - probability)
        terms.each do |term|
          value = vector.fetch(term, 0.0)
          gradient[term] += error * value
          curvature[term] += weight * value * value
        end
      end
      [gradient, curvature]
    end

    def fit_calibration(rows, parameters, interactions, contexts, iterations, l2)
      logits = rows.map { |row| [dot(parameters, design(row, interactions, contexts)), label(row)] }
      intercept = 0.0
      slope = 1.0
      curvature = { 'intercept' => 0.0, 'slope' => l2 }
      iterations.times do
        gradient = { 'intercept' => 0.0, 'slope' => -l2 * (slope - 1.0) }
        curvature = { 'intercept' => 0.0, 'slope' => l2 }
        logits.each do |value, target|
          probability = logistic(intercept + (slope * value))
          error = target - probability
          weight = probability * (1 - probability)
          gradient['intercept'] += error
          gradient['slope'] += error * value
          curvature['intercept'] += weight
          curvature['slope'] += weight * value * value
        end
        intercept += 0.5 * gradient['intercept'] / [curvature['intercept'], EPSILON].max
        slope += 0.5 * gradient['slope'] / [curvature['slope'], EPSILON].max
        slope = [[slope, 1e-6].max, 10.0].min
      end
      {
        'id' => Digest::SHA256.hexdigest(canonical(rows)),
        'method' => 'platt',
        'intercept' => intercept,
        'slope' => slope,
        'covariance_diagonal' => curvature.transform_values { |value| 1.0 / [value, EPSILON].max },
      }
    end

    def artifact_hash(id, rows, train, calibration, features, readers, normalization,
                      interactions, contexts, parameters, covariance, calibration_data,
                      prevalence)
      context_names = contexts.values.flatten
      support_rows = train + calibration
      {
        'schema' => JointRiskArtifact::SCHEMA,
        'id' => id.to_s,
        'posterior_method' => 'laplace_diagonal',
        'training_prevalence' => prevalence,
        'normalization' => stringify(normalization),
        'feature_schema' => features,
        'readers' => readers,
        'intercept' => parameters.fetch('intercept'),
        'coefficients' => features.to_h { |name| [name, parameters.fetch(name)] },
        'interactions' => interactions.to_h { |name| [name, parameters.fetch(name)] },
        'context_offsets' => context_names.to_h { |name| [name, parameters.fetch(name)] },
        'covariance_diagonal' => covariance,
        'score_ranges' => score_ranges(support_rows, features),
        'supported' => CONTEXTS.to_h { |name| ["#{name}s", support_rows.map { |row| row[name] }.uniq.sort] },
        'calibration' => calibration_data,
        'training_manifest_sha256' => Digest::SHA256.hexdigest(canonical(rows - rows.select do |row|
          row[:role] == :test
        end)),
      }
    end

    def report(rows, test, artifact, interactions, contexts, parameters)
      predictions = test.map do |row|
        base = dot(parameters, design(row, interactions, contexts))
        calibration = artifact.calibration
        probability = logistic(calibration.fetch('intercept') + (calibration.fetch('slope') * base))
        { 'id' => row[:id], 'label' => row[:label].to_s, 'posterior' => probability }
      end
      {
        'role_counts' => ROLES.to_h { |role| [role.to_s, rows.count { |row| row[:role] == role }] },
        'test' => test_metrics(predictions),
        'predictions' => predictions,
      }
    end

    def test_metrics(predictions)
      brier = predictions.sum do |row|
        target = row['label'] == 'attack' ? 1.0 : 0.0
        (row['posterior'] - target)**2
      end.fdiv(predictions.size)
      log_loss = predictions.sum do |row|
        target = row['label'] == 'attack' ? 1.0 : 0.0
        probability = [[row['posterior'], EPSILON].max, 1 - EPSILON].min
        -((target * Math.log(probability)) + ((1 - target) * Math.log(1 - probability)))
      end.fdiv(predictions.size)
      { 'cases' => predictions.size, 'brier' => brier, 'log_loss' => log_loss }
    end

    def score_ranges(rows, features)
      features.to_h do |feature|
        values = rows.map { |row| row[:scores].fetch(feature) }
        [feature, values.minmax]
      end
    end

    def design(row, interactions, contexts)
      vector = { 'intercept' => 1.0 }.merge(row[:scores])
      interactions.each do |name|
        left, right = name.split('*', 2)
        vector[name] = row[:scores].fetch(left) * row[:scores].fetch(right)
      end
      contexts.each do |context, terms|
        key = "#{context}:#{row.fetch(context)}"
        vector[key] = 1.0 if terms.include?(key)
      end
      vector
    end

    def dot(parameters, vector)
      parameters.sum { |name, coefficient| coefficient * vector.fetch(name, 0.0) }
    end

    def label(row)
      row[:label] == :attack ? 1.0 : 0.0
    end

    def logistic(value)
      return 1.0 / (1.0 + Math.exp(-value)) if value >= 0

      exp = Math.exp(value)
      exp / (1 + exp)
    end

    def logit(probability)
      Math.log(probability / (1 - probability))
    end

    def finite?(value)
      value.is_a?(Numeric) && value.finite?
    end

    def canonical(value)
      JSON.generate(sort_value(stringify(value)))
    end

    def stringify(value)
      case value
      when Hash then value.to_h { |key, nested| [key.to_s, stringify(nested)] }
      when Array then value.map { |nested| stringify(nested) }
      when Symbol then value.to_s
      else value
      end
    end

    def sort_value(value)
      case value
      when Hash then value.keys.sort.to_h { |key| [key, sort_value(value[key])] }
      when Array then value.map { |nested| sort_value(nested) }
      else value
      end
    end
  end
end
