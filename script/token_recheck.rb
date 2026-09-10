# frozen_string_literal: true

# Which single words are enough, on their own, to make a trained rail fire.
#
#   ruby script/token_recheck.rb
#
# A word on its own is not an attack. "ignore" is not an attack, "page" is not
# an attack, and a classifier that blocks either of them in isolation has
# learned a shortcut from a token straight through to a verdict rather than
# anything about instructions. Li et al. name that failure in InjecGuard
# (arXiv:2410.22770) and diagnose it exactly this way: put every token in the
# vocabulary through the trained model one at a time and read the list of the
# ones it condemns. They use the list to retrain; this uses it to audit, which
# is the half that needs no corpus.
#
# It is also the check that would have caught the regression this repository
# published for a month. The shipped Bayes artifact was regenerated and its
# false-alarm rate on real documentation went from 8.86% to 74.9% with nobody
# noticing, and the reason is visible in one run of this script: the features it
# weighs highest are "answer", "page", "as", "of", "that".
#
# Run it after every retraining. A trained artifact and an audit of it are one
# unit.
$LOAD_PATH.unshift(File.expand_path('../lib', __dir__))
require 'json'
require 'vangrail'

OUTPUT = ENV['OUTPUT'] || File.expand_path('../tmp/token_recheck.json', __dir__)

# Every rail that carries weights and can be asked about one word.
def rails
  [Vangrail::Rails::Bayes.new(sides: [:context])].select { |rail| rail.respond_to?(:score_for) }
end

# The vocabulary is the rail's own features, which for an n-gram model is the
# only set of inputs that can move it. A token outside it scores zero by
# construction and asking about it says nothing.
def vocabulary(rail)
  rail.respond_to?(:weights) ? rail.weights.keys : []
end

# Words that carry no intent in any document. Deliberately short and English:
# the point is not a complete stopword list, it is that a classifier condemning
# any word on this list has learned nothing about instructions.
SHARED = %w[a an and the of to in on for with is are was be been as at by from
            that this these those it its you your we our they their answer page
            all any not or if then so what which who how when where].freeze

def shared_word?(word)
  SHARED.include?(word.to_s.downcase)
end

report = { 'schema' => 'vangrail-token-recheck-v1', 'rails' => {} }

rails.each do |rail|
  vocab = vocabulary(rail)
  if vocab.empty?
    warn "#{rail.name}: no readable vocabulary, skipped"
    next
  end

  alone = vocab.filter_map do |token|
    result = rail.call(token, side: :context)
    next unless result.blocked?

    { 'token' => token, 'score' => rail.score_for(token).round(3) }
  end
  alone.sort_by! { |row| -row['score'] }

  # A stopword condemned on its own is the worst case, because it appears in
  # every document ever written and cannot carry intent.
  stopwords = alone.select { |row| Vangrail::NLP.words(row['token']).all? { |w| shared_word?(w) } }

  report['rails'][rail.name] = {
    'vocabulary' => vocab.size,
    'fire_alone' => alone.size,
    'rate' => (alone.size.to_f / vocab.size).round(4),
    'stopwords_that_fire_alone' => stopwords.size,
    'worst' => alone.first(20),
    'stopwords' => stopwords.first(20),
  }
end


File.write(OUTPUT, "#{JSON.pretty_generate(report)}\n")

report['rails'].each do |name, entry|
  puts format('%s: %d of %d features fire on their own (%.1f%%), %d of them carry no intent',
              name, entry['fire_alone'], entry['vocabulary'], entry['rate'] * 100,
              entry['stopwords_that_fire_alone'])
  entry['worst'].first(8).each { |row| puts format('  %-24s %+.2f', row['token'], row['score']) }
  unless entry['stopwords'].empty?
    puts '  words that cannot carry an instruction and fire anyway:'
    puts "    #{entry['stopwords'].map { |row| row['token'] }.join(', ')}"
  end
end
puts "written to #{OUTPUT}"
