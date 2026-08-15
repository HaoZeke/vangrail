# frozen_string_literal: true

require_relative 'result'

module Vangrail
  # Runs output rails while the answer is still arriving.
  #
  # An output rail that only runs on the finished text is a rail that runs after
  # the reader has read it. Streaming makes that worse, not better: the tokens
  # are on screen as they arrive, so the best a caller can do at the end is
  # withdraw text somebody has already seen, and a credential that appeared for
  # four seconds has appeared.
  #
  # So the deterministic rails run as the buffer grows, and they run often,
  # because they cost microseconds and cannot fail. A block stops the stream at
  # the chunk that crossed the line rather than at the end of the answer.
  #
  #   guard = Vangrail::StreamGuard.new(engine, user_input: question)
  #   stream.each do |chunk|
  #     verdict = guard.push(chunk)
  #     break if verdict&.blocked?
  #     emit(verdict&.content || chunk)
  #   end
  #   final = guard.finish
  #
  # The model-backed rails do not run per chunk. They cost a round trip, and
  # calling one every few tokens turns a two second answer into a minute. They
  # run once at `finish`, which is where the old behaviour still applies: a
  # block there is a retraction, and the caller has to say so.
  #
  # What this buys is bounded rather than total: everything the deterministic
  # rails can see is caught before display, and everything only a model can see
  # is caught at the end as before. That is worth stating plainly, because a
  # stream guard that implied otherwise would be the more dangerous thing.
  class StreamGuard
    # How much new text has to arrive before the rails look again. A rail that
    # runs per token spends more time in regexps than the model spends
    # generating; one that runs per paragraph lets a whole paragraph through.
    DEFAULT_INTERVAL = 40

    attr_reader :engine, :context, :buffer, :emitted, :checks

    def initialize(engine, interval: DEFAULT_INTERVAL, **context)
      @engine = engine
      @context = context
      @interval = interval
      @buffer = +''
      @emitted = 0
      @checks = 0
      @blocked = nil
      @modified = false
    end

    def blocked?
      !@blocked.nil?
    end

    # Adds a chunk and returns a Result when something changed, or nil when
    # there is nothing to say. A caller that ignores the return value gets the
    # old end-of-stream behaviour and nothing worse.
    def push(chunk)
      return @blocked if blocked?

      text = chunk.to_s
      return nil if text.empty?

      @buffer << text
      return nil unless due?

      inspect_buffer
    end

    # Everything the deterministic rails could not decide. Runs the full rail
    # set, model-backed ones included, over the finished answer.
    def finish
      return @blocked if blocked?

      result = engine.check_output(buffer, **context)
      @blocked = result if result.blocked?
      @buffer = result.content_or(buffer) if result.modified?
      result
    end

    # What the caller should show, given everything decided so far.
    def content
      buffer
    end

    private

    def due?
      buffer.length - @emitted >= @interval
    end

    # Only the rails that decide without a network call, and only over the text
    # that has arrived. A partial answer is not the same object a model rail was
    # written to judge: half a sentence looks unsupported because its citation
    # has not been generated yet, and blocking on that would refuse answers for
    # arriving slowly.
    def inspect_buffer
      @emitted = buffer.length
      @checks += 1
      offline = engine.output_rails.select { |r| r.offline? && r.applies_to?(:output) }
      return nil if offline.empty?

      partial = Engine.new(output: offline, on_error: engine.on_error, cache: false)
      result = partial.check_output(buffer, **context)

      if result.blocked?
        @blocked = result
        return result
      end
      return nil unless result.modified?

      @buffer = result.content_or(buffer)
      @modified = true
      result
    end
  end
end
