# frozen_string_literal: true

require_relative 'errors'
require_relative 'http'

module Vangrail
  # One OpenAI-compatible embeddings call.
  #
  # The sibling of Chat, and it exists for one reason: the lexicon rails read
  # words, and a synonym nobody listed is a miss. An embedding is the only cheap
  # way to compare two sentences by what they mean rather than by what they
  # spell, and every local proxy that serves chat can usually serve this too.
  #
  # Local first, exactly as with Chat. Sending every retrieved document to a
  # third party to be embedded is a data-flow decision an application should
  # make deliberately, and on a loopback proxy it is not one at all.
  #
  # Batched, because the cost that matters is round trips rather than tokens: a
  # page has a few dozen clauses, and thirty small requests to score one page is
  # what makes a rail too slow to leave on.
  class Embeddings
    PATH = '/embeddings'

    attr_reader :model, :http

    def initialize(model:, http: nil, base_url: nil, api_key: nil)
      @model = model
      @http = HTTP.build(http: http, base_url: base_url, api_key: api_key,
                         missing: 'an Embeddings needs a base_url or an http client')
    end

    # Vectors for each input, in the order given.
    #
    # The index is read rather than trusted to arrive in order: the API says
    # each datum carries one, and a provider batching internally is entitled to
    # answer out of order.
    def embed(texts)
      inputs = Array(texts).map(&:to_s)
      return [] if inputs.empty?

      body = http.post_json(PATH, { 'model' => model, 'input' => inputs })
      vectors = vectors_in(body)
      raise ProtocolError, "embeddings endpoint returned #{vectors.size} vectors for #{inputs.size} inputs" \
        unless vectors.size == inputs.size

      vectors
    end

    # Cosine similarity, which is what an embedding comparison is. Two vectors
    # of different length is a provider that changed model mid-call, and it is
    # an error rather than a zero.
    def self.cosine(left, right)
      raise ProtocolError, 'vectors of different lengths' unless left.size == right.size

      dot = 0.0
      left_norm = 0.0
      right_norm = 0.0
      left.each_with_index do |value, i|
        other = right[i]
        dot += value * other
        left_norm += value * value
        right_norm += other * other
      end
      return 0.0 if left_norm.zero? || right_norm.zero?

      dot / (Math.sqrt(left_norm) * Math.sqrt(right_norm))
    end

    private

    def vectors_in(body)
      data = body.is_a?(Hash) ? body['data'] : nil
      raise ProtocolError, 'embeddings endpoint returned no data array' unless data.is_a?(Array)

      ordered = data.each_with_index.sort_by { |datum, i| datum.is_a?(Hash) ? (datum['index'] || i) : i }
      ordered.map do |datum, _|
        vector = datum.is_a?(Hash) ? datum['embedding'] : nil
        raise ProtocolError, 'embeddings endpoint returned a datum with no embedding' unless vector.is_a?(Array)

        vector.map(&:to_f)
      end
    end
  end
end
