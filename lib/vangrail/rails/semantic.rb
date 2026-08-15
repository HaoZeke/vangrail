# frozen_string_literal: true

require_relative '../embeddings'
require_relative '../known_attacks'
require_relative '../nlp'
require_relative '../rail'

module Vangrail
  module Rails
    # Compares meaning rather than words, through whatever endpoint is already
    # configured.
    #
    # Rails::Paraphrase reaches exactly as far as the words in NLP::CONCEPTS,
    # and Rails::Similarity exactly as far as the wordings in KnownAttacks. Both
    # limits are the same limit written twice: a synonym nobody listed is a
    # miss. An embedding is the cheap way past it. "Countermand the guidance
    # issued to you" shares no listed word with "ignore all previous
    # instructions" and sits next to it in a vector space.
    #
    # This is the one rail here that is genuinely semantic, and it costs a round
    # trip, so it is opt-in and it runs beside the deterministic rails rather
    # than instead of them. When it cannot run it says so: an endpoint that
    # serves no embedding model, or refuses the call, produces passed with
    # certain? false, never a clean pass.
    #
    # On a loopback proxy it costs no money, keeps the retrieved text on the
    # machine, and adds one local call per document. On a third-party endpoint
    # it is a data-flow decision: every document screened is a document sent.
    # That is why nothing here picks an endpoint on its own.
    #
    # The threshold is the part that cannot ship measured. Cosine scores are a
    # property of the embedding model, not of this gem, so 0.75 is a starting
    # point rather than a finding: run script/embedding_probe.rb against the
    # endpoint you actually use, read the gap between its benign and attack
    # distributions, and set the number from that. A threshold nobody measured
    # on the model in use is a number, not a defence.
    class Semantic < Rail
      THRESHOLD = 0.75

      # Clauses shorter than this are not compared. A four-word fragment
      # embeds to something close to everything, and the score it produces is
      # noise that only ever costs a false positive.
      FLOOR = 24

      # An upper bound on the work one document can ask for. A long page has
      # hundreds of clauses, and embedding all of them turns one round trip into
      # a payload nobody budgeted for. The longest clauses are kept, because an
      # injected instruction is a sentence rather than a fragment.
      #
      # A page that exceeds it is not fully checked, and the result says so with
      # certain? false rather than with a footnote on a clean pass. That is the
      # same rule the rest of this gem follows: a partial check is not a check.
      MAX_CLAUSES = 64

      attr_reader :embeddings, :seeds, :threshold

      def initialize(embeddings:, seeds: KnownAttacks::ALL, threshold: THRESHOLD, floor: FLOOR,
                     max_clauses: MAX_CLAUSES, name: 'semantic', sides: %i[input context])
        super(name: name, sides: sides)
        @embeddings = embeddings
        @seeds = Array(seeds)
        @threshold = threshold
        @floor = floor
        @max_clauses = max_clauses
      end

      def offline?
        false
      end

      # Not memoizable across models or thresholds, and the text alone is not
      # the question being asked.
      def cache_key(text, _context)
        "#{embeddings.model}\n#{threshold}\n#{text}"
      end

      def call(text, _context)
        clauses, dropped = candidates(text)
        return pass if clauses.empty?

        score, seed, clause = nearest(clauses)
        if score < threshold
          return dropped.zero? ? pass : unchecked(cut_reason(dropped))
        end

        block(categories: ['semantic_match'],
              reason: format('reads as a known attack (%<score>.2f against "%<seed>s"): %<clause>s',
                             score: score, seed: seed, clause: clause[0, 80]))
      rescue Error => e
        unchecked("semantic check did not run: #{e.message}")
      end

      # The closest seed, its score, and the clause that matched, for a caller
      # that wants the number rather than the verdict. Raises what the transport
      # raises: a probe script wants the error, a rail wants a Result.
      def nearest(clauses)
        vectors = embeddings.embed(clauses)
        best = [-1.0, nil, nil]
        vectors.each_with_index do |vector, i|
          seed_vectors.each_with_index do |seed_vector, j|
            score = Embeddings.cosine(vector, seed_vector)
            best = [score, seeds[j], clauses[i]] if score > best.first
          end
        end
        best
      end

      # Embedded once per rail, on first use rather than at construction: a rail
      # that is never reached should never have called the endpoint, and an
      # engine built with no network available must still build.
      def seed_vectors
        @seed_vectors ||= embeddings.embed(seeds)
      end

      private

      def candidates(text)
        clauses = NLP.clauses(text).select { |clause| clause.length >= @floor }
        return [clauses, 0] if clauses.size <= @max_clauses

        kept = clauses.sort_by { |clause| -clause.length }.first(@max_clauses)
        [kept, clauses.size - kept.size]
      end

      # A rail that looked at part of a page has to say which part it skipped,
      # or the pass it returns claims more than it checked.
      def cut_reason(dropped)
        "checked the #{@max_clauses} longest clauses; #{dropped} shorter ones were not embedded"
      end
    end
  end
end
