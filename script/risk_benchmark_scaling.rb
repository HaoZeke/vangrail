# frozen_string_literal: true

module Vangrail
  # Adversarial work dimensions and scaling curves for RiskBenchmark.
  module RiskBenchmarkScaling
    CLAUSE_COUNTS = [1, 4, 16, 64].freeze
    UNICODE_DENSITIES = [0.0, 0.25, 0.5, 1.0].freeze
    FAN_OUT_COUNTS = [1, 2, 4, 8].freeze
    CACHE_CARDINALITIES = [1, 64, 256, 512].freeze
    ORDINARY_GUIDANCE = 'ordinary guidance'

    private

    def shape_for(text, normalised)
      characters = text.length
      non_ascii = text.each_char.count { |character| !character.ascii_only? }
      {
        'characters' => characters,
        'bytes' => text.bytesize,
        'clauses' => NLP.clauses(text).size,
        'unicode_density' => characters.zero? ? 0.0 : non_ascii.fdiv(characters),
        'variants' => 1,
        'rails' => 1,
        'cache_cardinality' => 1,
        'normalised_characters' => normalised.length,
      }
    end

    def work_for(words, normalised)
      windows = if normalised.length > 4
                  ((normalised.length - 4) / LinearModel::STRIDE) + 1
                else
                  0
                end
      {
        'tokens' => words.size,
        'bigrams' => [words.size - 1, 0].max,
        'character_windows' => windows,
      }
    end

    def scaling_profiles(model)
      text_length_curves(model) + clause_curves(model) + unicode_curves(model) +
        variant_curves(model) + rail_curves + cache_curves
    end

    def text_length_curves(model)
      scoring_implementations.flat_map do |implementation|
        lengths.map do |length|
          text = text_for(length)
          scale_row('text_length', length, implementation,
                    shape_for(text, NLP.normalize(text)), length) do
            score_with(model, text, implementation)
          end
        end
      end
    end

    def clause_curves(model)
      scoring_implementations.flat_map do |implementation|
        CLAUSE_COUNTS.map do |count|
          text = Array.new(count, ORDINARY_GUIDANCE).join('. ') << '.'
          scale_row('clause_count', count, implementation,
                    { 'clauses' => count, 'characters' => text.length }, count) do
            score_with(model, text, implementation)
          end
        end
      end
    end

    def unicode_curves(model)
      length = [lengths.max, 1024].min
      scoring_implementations.flat_map do |implementation|
        UNICODE_DENSITIES.map do |density|
          unicode = (length * density).round
          text = ('é' * unicode) + ('a' * (length - unicode))
          scale_row('unicode_density', density, implementation,
                    { 'characters' => length, 'bytes' => text.bytesize, 'unicode_density' => density }, length) do
            score_with(model, text, implementation)
          end
        end
      end
    end

    def variant_curves(model)
      length = [lengths.max, 256].min
      scoring_implementations.flat_map do |implementation|
        FAN_OUT_COUNTS.map do |count|
          variants = Array.new(count) { |index| variant_text(length, index) }
          scale_row('variant_count', count, implementation,
                    { 'variants' => count, 'characters_each' => length }, count) do
            variants.sum { |text| score_with(model, text, implementation) }
          end
        end
      end
    end

    def rail_curves
      FAN_OUT_COUNTS.map do |count|
        engine = scaling_engine(count)
        text = 'ordinary handbook guidance for a routine batch job'
        scale_row('rail_count', count, 'ruby',
                  { 'rails' => count, 'characters' => text.length }, count) do
          engine.check_input(text).passed? ? count : -1
        end
      end
    end

    def cache_curves
      CACHE_CARDINALITIES.map do |count|
        limit = ResultCache::DEFAULT_LIMIT
        retained = fill_cache(count, limit)
        scale_row('cache_cardinality', count, 'ruby',
                  { 'cache_limit' => limit, 'retained_entries' => retained }, count) do
          fill_cache(count, limit)
        end
      end
    end

    def scale_row(dimension, value, implementation, shape, items, &)
      row = measure("scale_#{dimension}", implementation, shape, { 'items' => items }, &)
      row.merge('dimension' => dimension, 'value' => value)
    end

    def scoring_implementations
      implementations = ['ruby']
      implementations << 'native' if Native.available?
      implementations
    end

    def score_with(model, text, implementation)
      implementation == 'native' ? model.score(text) : model.ruby_score(text)
    end

    def variant_text(length, index)
      suffix = " #{index.to_s(36)}"
      "#{text_for(length - suffix.length)}#{suffix}"
    end

    def scaling_engine(count)
      pattern = { 'never_matches' => /\Athis text never appears\z/ }
      rails = Array.new(count) do |index|
        Rails::Pattern.new(patterns: pattern, name: "scaling_pattern_#{index}", sides: [:input])
      end
      Engine.new(input: rails, cache: false)
    end

    def fill_cache(count, limit)
      cache = ResultCache.new(limit: limit)
      result = Result.passed(rail: 'scaling')
      count.times { |index| cache.fetch(:input, 'scaling', index) { result } }
      cache.size
    end

    def scaling_analysis(rows)
      groups = rows.group_by { |row| [row.fetch('dimension'), row.fetch('implementation')] }
      groups.map do |(dimension, implementation), group|
        ordered = group.sort_by { |row| row.fetch('work').fetch('items') }
        smallest = ordered.first
        largest = ordered.last
        work_growth = largest.dig('work', 'items').fdiv(smallest.dig('work', 'items'))
        latency_growth = largest.dig('summary', 'latency_ms', 'median')
                                .fdiv(smallest.dig('summary', 'latency_ms', 'median'))
        {
          'dimension' => dimension,
          'implementation' => implementation,
          'work_growth' => work_growth,
          'latency_growth' => latency_growth,
          'latency_growth_per_work_growth' => latency_growth / work_growth,
        }
      end
    end
  end
end
