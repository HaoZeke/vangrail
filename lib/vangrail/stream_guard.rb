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

    def buffer
      @buffer
    end

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
        @blocked = result
        return result
      end

      unless result.modified?
        @checked = buffer.length
        return nil
      end

      @buffer = result.content_or(buffer)
      @checked = buffer.length
      result
    end
  end
end
