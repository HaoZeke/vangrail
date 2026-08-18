# frozen_string_literal: true

module Vangrail
  # Bounded in-process memo for rail results.
  #
  # A reader who rephrases, retries, or clicks a suggested follow-up sends text
  # a rail has already judged, and each repeat costs another round trip. Keyed on
  # side, rail name, and whatever that rail says its decision depends on, so a
  # changed model or a changed policy never reads a stale decision.
  #
  # Only decided results are stored. A result with `certain? == false` records a
  # rail that failed or did not run, and caching that would turn one unlucky
  # moment into a session-long hole.
  class ResultCache
    DEFAULT_LIMIT = 256

    attr_reader :limit, :hits, :misses

    def initialize(limit: DEFAULT_LIMIT)
      @limit = limit
      @store = {}
      @hits = 0
      @misses = 0
      @mutex = Mutex.new
    end

    # Yields on a miss and stores what the block returns. Hits move to the
    # newest slot so the oldest unused key is the one `shift` drops.
    def fetch(side, name, key)
      store_key = [side, name, key]
      hit = @mutex.synchronize do
        next unless @store.key?(store_key)

        @hits += 1
        value = @store.delete(store_key)
        @store[store_key] = value
        value
      end
      return hit if hit

      @mutex.synchronize { @misses += 1 }
      result = yield
      store(store_key, result)
      result
    end

    def size
      @mutex.synchronize { @store.size }
    end

    def clear
      @mutex.synchronize { @store.clear }
    end

    def to_h
      { 'size' => size, 'limit' => limit, 'hits' => hits, 'misses' => misses }
    end

    private

    # A stored result is handed to every later caller with the same key, so its
    # rewritten text is shared and must not be writable. Freezing turns a caller
    # that appends to it into an immediate FrozenError rather than one turn's
    # words appearing inside another turn's answer, hundreds of requests later
    # and nowhere near the append.
    def store(key, result)
      return unless result.respond_to?(:certain?) && result.certain?

      result.content.freeze if result.respond_to?(:content) && result.content.is_a?(String)

      @mutex.synchronize do
        # Ruby hashes keep insertion order, so the oldest key is the first one.
        @store.delete(key)
        @store.shift while @store.size >= limit
        @store[key] = result
      end
    end
  end
end
