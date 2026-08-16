# frozen_string_literal: true

# Measures the origin cut against treating every span as a user attack.
#
#   ruby script/measure_origin.rb
#
# Same 270/48 texts as script/measure_evidence.rb. Three questions, none
# of them a catch rate:
#
#   1. If these pages are labeled data, how often does the attack
#      posterior stay put while contamination moves?
#   2. If the same pages are mis-labeled as user (the detector stack),
#      how often does the attack posterior move?
#   3. After a clean question, how often does admit?(:shell) stay false
#      when the page is the argument?
#
# Numbers are printed. They are this corpus. They are not AgentDojo.

$LOAD_PATH.unshift(File.expand_path('../lib', __dir__))
require 'vangrail'
require_relative 'handbook_corpus'

def attack_corpus
  HandbookCorpus.attack_texts
end

def benign_corpus
  HandbookCorpus.benign_texts
end

PRIOR = 1e-3
QUESTION = 'How do I submit a GPU job?'

def engine
  Vangrail::Engine.new(input: Vangrail::Builder.deterministic(:input),
                       context: Vangrail::Builder.deterministic(:context))
end

def session
  Vangrail::Session.new(engine: engine, prior: PRIOR)
end

def count(texts)
  env = engine
  attack_moved = 0
  contamination_moved = 0
  attack_stayed = 0
  mislabeled_moved = 0
  shell_refused = 0
  gate = Vangrail::Admission.new(allow: { cite: %i[data], search: [] })
  question = Vangrail::Cell.user(QUESTION)

  texts.each do |text|
    data = env.assess(text, side: :context, prior: PRIOR, origin: :data)
    user = env.assess(text, side: :context, prior: PRIOR, origin: :user)
    cut = session
    cut.observe(QUESTION, side: :input, origin: :user)
    before = cut.attack.posterior
    cut.fold(data)
    attack_stayed += 1 if (cut.attack.posterior - before).abs < 1e-12
    contamination_moved += 1 if cut.contamination.posterior > PRIOR
    attack_moved += 1 if cut.attack.posterior > before + 1e-12
    mislabeled_moved += 1 if user.posterior > PRIOR
    shell_refused += 1 unless gate.permit?(:shell, request: question, arguments: Vangrail::Cell.data(text))
  end

  {
    n: texts.size,
    attack_stayed: attack_stayed,
    contamination_moved: contamination_moved,
    attack_moved: attack_moved,
    mislabeled_moved: mislabeled_moved,
    shell_refused: shell_refused,
  }
end

attacks = attack_corpus
benign = benign_corpus
puts "attacks #{attacks.size}  benign #{benign.size}  prior #{PRIOR}"
[[:attacks, attacks], [:benign, benign]].each do |label, texts|
  row = count(texts)
  puts format(
    '%<label>s n=%<n>d  cut_attack_stayed=%<attack_stayed>d  ' \
    'cut_contamination_moved=%<contamination_moved>d  ' \
    'cut_attack_moved=%<attack_moved>d  ' \
    'detector_as_user_moved=%<mislabeled_moved>d  ' \
    'shell_refused=%<shell_refused>d',
    label: label, **row,
  )
end
