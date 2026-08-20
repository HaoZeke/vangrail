# frozen_string_literal: true

module Vangrail
  # The Beta distribution, enough of it to put an honest interval on a rate.
  #
  # A rail that fired on 0 of 48 benign texts has a false-alarm rate somewhere
  # below about one in twenty, and nothing in the corpus says where. Reporting
  # the point estimate treats "I measured nothing" as "the rate is the smoothing
  # constant", which is exactly the direction that flatters a detector.
  #
  # The Bayesian answer is the one from the estimation literature that language
  # modelling has used since Good: the rate is not a number, it is a posterior,
  # and with a Beta prior over a binomial count that posterior is a Beta. Taking
  # its pessimistic tail rather than its mean gives a bound that shrinks as the
  # corpus grows and stays conservative while it is small.
  #
  # Implemented here rather than pulled in, because the runtime has no
  # dependencies: the regularised incomplete beta function by the standard
  # continued fraction, and its inverse by bisection, which is slow and exact
  # enough for a table computed once.
  module Beta
    ITERATIONS = 200
    EPSILON = 1e-12
    TINY = 1e-300

    module_function

    # P(X <= x) for X ~ Beta(a, b): the regularised incomplete beta function.
    def cdf(x, a, b)
      return 0.0 if x <= 0
      return 1.0 if x >= 1

      front = front_factor(x, a, b)
      # The continued fraction converges quickly on one side of the mode and
      # slowly on the other, so the far side is computed from the symmetry.
      if x < (a + 1) / (a + b + 2)
        front * continued_fraction(x, a, b) / a
      else
        1 - (front * continued_fraction(1 - x, b, a) / b)
      end
    end

    def front_factor(x, a, b)
      Math.exp(Math.lgamma(a + b).first - Math.lgamma(a).first - Math.lgamma(b).first +
               (a * Math.log(x)) + (b * Math.log(1 - x)))
    end

    # The value below which a Beta(a, b) sits with probability `p`.
    #
    # Bisection rather than Newton: this runs once per rail per confidence
    # level, the function is monotone, and fifty halvings put it well inside any
    # precision a likelihood ratio needs.
    def quantile(p, a, b)
      return 0.0 if p <= 0
      return 1.0 if p >= 1

      low = 0.0
      high = 1.0
      60.times do
        mid = (low + high) / 2
        if cdf(mid, a, b) < p
          low = mid
        else
          high = mid
        end
      end
      (low + high) / 2
    end

    # Lentz's algorithm for the continued fraction of the incomplete beta.
    def continued_fraction(x, a, b)
      qab = a + b
      qap = a + 1
      qam = a - 1
      c = 1.0
      d = 1 - (qab * x / qap)
      d = TINY if d.abs < TINY
      d = 1 / d
      h = d

      (1..ITERATIONS).each do |m|
        m2 = 2 * m
        numerator = m * (b - m) * x / ((qam + m2) * (a + m2))
        c, d, step = fraction_step(numerator, c, d)
        h *= step

        numerator = -(a + m) * (qab + m) * x / ((a + m2) * (qap + m2))
        c, d, step = fraction_step(numerator, c, d)
        h *= step
        break if (step - 1).abs < EPSILON
      end
      h
    end

    def fraction_step(numerator, coefficient, denominator)
      denominator = 1 + (numerator * denominator)
      denominator = TINY if denominator.abs < TINY
      coefficient = 1 + (numerator / coefficient)
      coefficient = TINY if coefficient.abs < TINY
      denominator = 1 / denominator
      [coefficient, denominator, denominator * coefficient]
    end
  end
end
