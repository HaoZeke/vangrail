# frozen_string_literal: true

# Scores Rails::Grounding against a published hallucination corpus.
#
#   ruby script/fetch_external.rb && ruby script/measure_grounding.rb
#
# The coverage page has said "misinformation: covered" since the rail was
# written, and no number stood behind it. This is the number.
#
# RAGTruth (Niu et al., ACL 2024) is the corpus: responses generated for
# question answering, data-to-text and summarisation over given passages, with
# every hallucinated span annotated by hand. A response carrying at least one
# annotated span is a hallucination at the response level, which is the decision
# this rail makes, and 35% of the test split carries one.
#
# What the published baselines score at the response level, so a number here can
# be read against something (Niu et al. Table 5, and Kovacs et al. 2025 for the
# encoder line):
#
#   prompting, weaker judge          F1 12.8
#   prompting, stronger judge        F1 28.3
#   fine-tuned Llama-2-13B           F1 52.7
#   Luna, an encoder                 F1 65.4
#   LettuceDetect large              F1 79.2
#
# This rail is a prompt baseline. It is the first two rows of that table by
# construction, and the reason to measure it is to know which one.
#
#   SAMPLE=300  responses to score, balanced across the three task types
#   MODEL=...   the judge
$LOAD_PATH.unshift(File.expand_path('../lib', __dir__))
require 'json'
require 'vangrail'

DATA = ENV['DATA'] || File.expand_path('../tmp/external', __dir__)
OUTPUT = ENV['OUTPUT'] || File.expand_path('../tmp/grounding_results.json', __dir__)
SAMPLE = (ENV['SAMPLE'] || 300).to_i
SEED = (ENV['SEED'] || 7).to_i

responses = File.join(DATA, 'ragtruth_response.jsonl')
sources = File.join(DATA, 'ragtruth_source_info.jsonl')
abort "no RAGTruth in #{DATA}; run: ruby script/fetch_external.rb" unless File.file?(responses)

source_by_id = {}
File.foreach(sources) do |line|
  row = JSON.parse(line)
  source_by_id[row['source_id']] = row
end

# The test split only. The train split is what the fine-tuned baselines above
# were fitted on, and scoring a judge on it would not be comparable with them.
rows = []
File.foreach(responses) do |line|
  row = JSON.parse(line)
  next unless row['split'] == 'test'

  source = source_by_id[row['source_id']]
  next unless source

  rows << { 'id' => row['id'], 'task' => source['task_type'], 'response' => row['response'].to_s,
            'passages' => [source['source_info'].is_a?(String) ? source['source_info'] : JSON.generate(source['source_info'])],
            'hallucinated' => !Array(row['labels']).empty? }
end

# Balanced across the three task types, because the corpus is not balanced and
# the tasks are not equally hard: the published baselines lose most of their
# recall on summarisation.
random = Random.new(SEED)
per_task = (SAMPLE / rows.map { |r| r['task'] }.uniq.size.to_f).ceil
sampled = rows.group_by { |r| r['task'] }.flat_map { |_task, group| group.shuffle(random: random).first(per_task) }
sampled = sampled.shuffle(random: random).first(SAMPLE)

provider = Vangrail::Provider.resolve
abort 'no provider resolved; set the endpoint environment for a model-backed rail' unless provider

model = ENV['MODEL'] || provider.model(:judge)
rail = Vangrail::Rails::Grounding.new(provider: provider, model: model)
warn "judge: #{model} at #{provider.base_url}"
warn "#{sampled.size} responses, #{sampled.count { |r| r['hallucinated'] }} hallucinated"

counts = Hash.new(0)
detail = []
sampled.each_with_index do |row, i|
  result = rail.call(row['response'], side: :output, passages: row['passages'],
                     user_input: row['question'].to_s)
  flagged = result.blocked?
  truth = row['hallucinated']
  counts[:tp] += 1 if flagged && truth
  counts[:fp] += 1 if flagged && !truth
  counts[:fn] += 1 if !flagged && truth
  counts[:tn] += 1 if !flagged && !truth
  counts[:unchecked] += 1 unless result.certain?
  detail << { 'id' => row['id'], 'task' => row['task'], 'hallucinated' => truth,
              'flagged' => flagged, 'certain' => result.certain?, 'reason' => result.reason }
  warn "  #{i + 1} of #{sampled.size}" if ((i + 1) % 25).zero?
end

precision = counts[:tp].zero? ? 0.0 : counts[:tp].to_f / (counts[:tp] + counts[:fp])
recall = counts[:tp].zero? ? 0.0 : counts[:tp].to_f / (counts[:tp] + counts[:fn])
f1 = (precision + recall).zero? ? 0.0 : 2 * precision * recall / (precision + recall)

by_task = detail.group_by { |row| row['task'] }.transform_values do |group|
  tp = group.count { |r| r['flagged'] && r['hallucinated'] }
  fp = group.count { |r| r['flagged'] && !r['hallucinated'] }
  fn = group.count { |r| !r['flagged'] && r['hallucinated'] }
  p = tp.zero? ? 0.0 : tp.to_f / (tp + fp)
  r = tp.zero? ? 0.0 : tp.to_f / (tp + fn)
  { 'n' => group.size, 'precision' => p.round(3), 'recall' => r.round(3),
    'f1' => ((p + r).zero? ? 0.0 : 2 * p * r / (p + r)).round(3) }
end

report = {
  'schema' => 'vangrail-grounding-v1', 'model' => model, 'sample' => sampled.size, 'seed' => SEED,
  'source' => 'RAGTruth test split, response-level hallucination (Niu et al., ACL 2024)',
  'counts' => counts.transform_keys(&:to_s),
  'precision' => precision.round(3), 'recall' => recall.round(3), 'f1' => f1.round(3),
  'by_task' => by_task, 'rows' => detail,
}
File.write(OUTPUT, "#{JSON.pretty_generate(report)}\n")

puts format('grounding  precision %.3f  recall %.3f  F1 %.3f  over %d responses (%d hallucinated)',
            precision, recall, f1, sampled.size, counts[:tp] + counts[:fn])
puts format('           tp %d  fp %d  fn %d  tn %d  unchecked %d',
            counts[:tp], counts[:fp], counts[:fn], counts[:tn], counts[:unchecked])
by_task.each { |task, e| puts format('           %-10s n=%-4d P %.3f  R %.3f  F1 %.3f', task, e['n'], e['precision'], e['recall'], e['f1']) }
puts 'published response-level F1 (Niu et al. Table 5, Kovacs et al.): prompting 12.8 and 28.3, fine-tuned 52.7, Luna 65.4, LettuceDetect 79.2'
puts "written to #{OUTPUT}"
