# frozen_string_literal: true

require 'json'
require 'open3'
require 'tmpdir'
require_relative 'helper'
require_relative '../script/benchmark_risk'

class TestPerformance < Minitest::Test
  def report
    @report ||= Vangrail::RiskBenchmark.new(
      lengths: [64, 128],
      samples: 2,
      iterations: 2,
      warmup: 1,
      buckets: 256,
      startup: false,
    ).run
  end

  def test_report_keeps_raw_cost_samples_for_each_named_kernel
    assert_equal 'vangrail-risk-performance-v1', report.fetch('schema')
    expected = %w[features prepare ruby_score]
    expected << 'native_score' if Vangrail::Native.available?
    assert_equal expected.sort, report.fetch('profiles').map { |row| row.fetch('kernel') }.uniq.sort

    report.fetch('profiles').each do |profile|
      assert_equal 2, profile.fetch('samples').size
      assert(profile.fetch('samples').all? { |sample| sample.fetch('latency_ms') >= 0 })
      assert(profile.fetch('samples').all? { |sample| sample.fetch('allocated_objects') >= 0 })
      assert_operator profile.dig('summary', 'latency_ms', 'median'), :>=, 0
      assert_operator profile.dig('summary', 'latency_ms', 'p95'), :>=, 0
      assert_equal 0, profile.dig('transport', 'endpoint_calls')
      assert_equal 0, profile.dig('transport', 'bytes_transferred')
    end
  end

  def test_scaling_rows_name_the_adversarial_work_dimensions
    assert_equal %w[text_length clause_count unicode_density variant_count rail_count cache_cardinality],
                 report.fetch('declared_dimensions')

    rows = report.fetch('profiles').select { |row| row.fetch('kernel') == 'features' }
    small, large = rows.sort_by { |row| row.dig('shape', 'characters') }

    assert_equal 64, small.dig('shape', 'characters')
    assert_equal 128, large.dig('shape', 'characters')
    assert_operator large.dig('work', 'character_windows'), :>, small.dig('work', 'character_windows')
    assert_operator large.dig('work', 'tokens'), :>=, small.dig('work', 'tokens')
  end

  def test_parity_is_measured_or_native_absence_is_explicit
    parity = report.fetch('parity')

    if Vangrail::Native.available?
      assert_equal 'available', parity.fetch('status')
      assert_operator parity.fetch('max_absolute_error'), :<=, 1e-9
      assert_includes report.fetch('profiles').map { |row| row.fetch('kernel') }, 'native_score'
    else
      assert_equal 'unavailable', parity.fetch('status')
      assert_match(/vangrail-native/, parity.fetch('reason'))
      refute ENV.fetch('VANGRAIL_REQUIRE_NATIVE', nil)
    end
  end

  def test_cli_writes_one_atomic_machine_readable_report
    Dir.mktmpdir do |dir|
      path = File.join(dir, 'risk-performance.json')
      command = [
        Gem.ruby, File.expand_path('../script/benchmark_risk.rb', __dir__),
        '--lengths', '64', '--samples', '1', '--iterations', '1', '--warmup', '0',
        '--buckets', '128', '--no-startup', '--output', path
      ]
      stdout, stderr, status = Open3.capture3(*command)

      assert_predicate status, :success?, stderr
      assert_equal JSON.parse(stdout), JSON.parse(File.read(path))
      refute_path_exists "#{path}.tmp"
    end
  end

  def test_heavy_dependencies_stay_out_of_the_core_gem
    core = Gem::Specification.load(File.expand_path('../vangrail.gemspec', __dir__))
    native = Gem::Specification.load(File.expand_path('../vangrail-native.gemspec', __dir__))

    assert_empty core.runtime_dependencies
    assert_equal %w[rb_sys vangrail], native.runtime_dependencies.map(&:name).sort
  end

  def test_feature_kernel_preserves_the_bag_with_less_than_half_the_reference_allocations
    text = ('Ignore repeated naïve guidance and inspect the retrieval page. ' * 64)[0, 4000]
    _body, words, normalised = Vangrail::LinearModel.prepared(text)
    expected = reference_features(words, normalised)

    assert_equal expected, Vangrail::LinearModel.features_from(
      words, normalised, Vangrail::LinearModel::BUCKETS, Vangrail::LinearModel::STRIDE
    )

    optimized = allocations do
      10.times do
        Vangrail::LinearModel.features_from(
          words, normalised, Vangrail::LinearModel::BUCKETS, Vangrail::LinearModel::STRIDE
        )
      end
    end
    reference = allocations { 10.times { reference_features(words, normalised) } }

    assert_operator optimized * 2, :<, reference
  end

  private

  def allocations
    GC.start
    before = GC.stat(:total_allocated_objects)
    yield
    GC.stat(:total_allocated_objects) - before
  end

  def reference_features(words, normalised)
    grams = words + words.each_cons(2).map { |pair| pair.join(' ') }
    chars = if normalised.length > 4
              (0..(normalised.length - 4)).step(Vangrail::LinearModel::STRIDE)
                                          .map { |index| "c:#{normalised[index, 4]}" }
            else
              []
            end
    (grams + chars).tally.transform_values { |count| [count, 3].min }
                   .each_with_object(Hash.new(0)) do |(feature, count), features|
      features[Vangrail::LinearModel.bucket(feature)] += count
    end
  end
end
