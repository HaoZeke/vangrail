# frozen_string_literal: true

require_relative 'helper'

# The Beta distribution, checked against the cases with closed forms.
#
# Everything that puts an honest interval on a measured rate rests on these two
# functions, and a continued fraction that is subtly wrong is a continued
# fraction that reports plausible numbers for years.
class TestBeta < Minitest::Test
  include GuardrailsTest

  B = Vangrail::Beta

  # Beta(1, 1) is the uniform distribution, and Beta(a, 1) and Beta(1, b) have
  # closed forms: x**a and 1 - (1 - x)**b.
  def test_the_cdf_matches_the_closed_forms
    assert_in_delta 0.3, B.cdf(0.3, 1, 1), 1e-9
    assert_in_delta 0.25**3, B.cdf(0.25, 3, 1), 1e-9
    assert_in_delta 1 - (0.6**4), B.cdf(0.4, 1, 4), 1e-9
    # Symmetric case, from the regularised incomplete beta tables.
    assert_in_delta 0.5, B.cdf(0.5, 2, 2), 1e-9
    assert_in_delta 0.890625, B.cdf(0.5, 2, 5), 1e-9
  end

  def test_the_cdf_is_monotone_and_bounded
    values = (0..20).map { |i| B.cdf(i / 20.0, 2.5, 7.5) }

    assert_equal values.sort, values
    assert_in_delta 0.0, values.first, 1e-12
    assert_in_delta 1.0, values.last, 1e-12
  end

  def test_the_quantile_inverts_the_cdf
    [[0.5, 1, 1], [2.5, 7.5, 0.2], [0.5, 48.5, 0.95]].each do |a, b, _|
      [0.05, 0.5, 0.95].each do |p|
        x = B.quantile(p, a, b)

        assert_in_delta p, B.cdf(x, a, b), 1e-6, "quantile(#{p}, #{a}, #{b}) did not invert"
      end
    end
  end

  def test_the_edges_are_answered_rather_than_computed
    assert_in_delta 0.0, B.cdf(-1, 2, 2), 1e-12
    assert_in_delta 1.0, B.cdf(2, 2, 2), 1e-12
    assert_in_delta 0.0, B.quantile(0, 2, 2), 1e-12
    assert_in_delta 1.0, B.quantile(1, 2, 2), 1e-12
  end

  # The case the whole thing exists for: no hits in a small sample bounds the
  # rate well above zero, and the bound tightens as the sample grows.
  def test_no_hits_still_bounds_the_rate_and_the_bound_shrinks_with_the_corpus
    small = B.quantile(0.95, 0.5, 48.5)
    large = B.quantile(0.95, 0.5, 4800.5)

    assert_operator small, :>, 0.03
    assert_operator small, :<, 0.05
    assert_operator large, :<, small / 50
  end
end
