# frozen_string_literal: true

require_relative 'engine'
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
  #     emit(guard.take)
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

    attr_reader :engine, :context, :emitted, :checked, :checks

    def initialize(engine, interval: DEFAULT_INTERVAL, **context)
      @engine = engine
      @context = context
      @interval = interval
      @buffer = +''
      @emitted = 0
      @checked = 0
      @checks = 0
      @blocked = nil
      @released = +''
      # Rewrites happen in two places: the per-chunk pass, which runs its own
      # Engine over the offline rails, and `finish`, which runs the caller's. A
      # result from either one only knows about its own pass, so a redaction
      # applied mid-stream was missing from the report at the end.
      @rewritten_by = []
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
      result = merge_rewrites(result)
      @blocked = result if result.blocked?
      # Duplicated, because the buffer is appended to in place and a rewrite
      # hands back a string the rail may still own. A memoized rail returns the
      # same Result to the next caller with the same text, so appending to its
      # content puts one turn's tokens inside another turn's answer.
      @buffer = result.content_or(buffer).dup if result.modified?
      @checked = buffer.length unless result.blocked?
      result
    end

    # The prefix a rail has read. The unread tail stays in the buffer.
    def content
      @buffer[0, @checked].to_s
    end

    # Text the caller has not been given yet, and that a rail has read.
    #
    # The second half of that sentence is the point. Only the inspected prefix
    # is handed out: the tail that has arrived since the last check is held
    # back until a check covers it, or until `finish`. Releasing it early would
    # put text on screen that no rail has seen, which is the failure this class
    # exists to prevent, and it is easy to write by accident because the buffer
    # is right there.
    #
    # The cost is that up to `interval` characters lag behind the model. The
    # alternative is a guard that streams the credential and redacts it
    # afterwards.
    #
    # After a rewrite that keeps the already-shown prefix, this returns only
    # the new suffix. After one that changes what was already shown, it returns
    # the whole checked buffer, because the prefix on screen is no longer true.
    def take
      current = content
      if @released.empty? || current.start_with?(@released)
        out = current[@released.length..] || ''
        @released = current.dup
        return out
      end

      @released = current.dup
      current
    end

    private

    # Every rail that rewrote the answer, across both passes. The union rather
    # than the last pass's list, because a mid-stream redaction and an
    # end-of-stream mark are both true of the answer the reader received.
    def merge_rewrites(result)
      return result unless result.respond_to?(:rewritten_by)

      union = @rewritten_by | result.rewritten_by
      return result if union == result.rewritten_by

      result.with_rewrites(union)
    end

    def buffer
      @buffer
    end

    def due?
      buffer.length - @emitted >= @interval
    end

    # Only the rails that decide without a network call and can read a fragment,
    # and only over the text that has arrived. A partial answer is not the same
    # object a model rail was written to judge: half a sentence looks
    # unsupported because its citation has not been generated yet, and blocking
    # on that would refuse answers for arriving slowly. A rail that marks
    # finished text is left out for the same reason from the other direction:
    # what it would mark is not finished.
    def inspect_buffer
      @emitted = buffer.length
      @checks += 1
      offline = engine.output_rails.select do |r|
        r.offline? && r.incremental? && r.applies_to?(:output)
      end
      # Nothing can object mid-stream, so the text is as checked as it is going
      # to get before `finish`, and holding it back would stall the stream for
      # no reason.
      if offline.empty?
        @checked = buffer.length
        return nil
      end

      partial = Engine.new(output: offline, on_error: engine.on_error, cache: false)
      result = partial.check_output(buffer, **context)

      if result.blocked?
        @blocked = merge_rewrites(result)
        return @blocked
      end

      unless result.modified?
        @checked = buffer.length if result.certain?
        return nil
      end

      @rewritten_by |= result.rewritten_by if result.respond_to?(:rewritten_by)
      @buffer = result.content_or(buffer).dup
      @checked = buffer.length
      result
    end
  end
end
