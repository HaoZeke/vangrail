# frozen_string_literal: true

require 'json'
require 'socket'

# A one-connection-at-a-time HTTP server for tests that need a real socket.
#
# The unit suite drives Vangrail::HTTP through a double, which never
# exercises header writing, chunk reading, status handling, or JSON on the wire.
# This does, on an ephemeral loopback port, with no gem outside the standard
# library so the test suite keeps the same promise the gem makes.
class FakeServer
  # `verb` rather than `method`: a Struct member called `method` shadows
  # Object#method, and a test double that breaks reflection is a bad trade
  # for one familiar word.
  Request = Struct.new(:verb, :path, :body, keyword_init: true) do
    def json
      body.to_s.empty? ? {} : JSON.parse(body)
    end
  end

  attr_reader :requests

  # The block receives a Request and returns [status, body_hash_or_string].
  def initialize(&handler)
    @handler = handler
    @server = TCPServer.new('127.0.0.1', 0)
    @requests = []
    @thread = Thread.new { serve }
    @thread.abort_on_exception = false
  end

  def base_url
    "http://127.0.0.1:#{@server.addr[1]}"
  end

  def close
    @closing = true
    @server.close unless @server.closed?
    @thread.kill
  end

  # Runs the block with a live server and always closes the listener.
  def self.with(handler)
    server = new(&handler)
    begin
      yield server
    ensure
      server.close
    end
  end

  private

  def serve
    loop do
      break if @closing

      socket = @server.accept
      handle(socket)
    rescue IOError, Errno::EBADF, Errno::EINVAL
      break
    ensure
      socket&.close unless socket&.closed?
    end
  end

  def handle(socket)
    request_line = socket.gets
    return if request_line.nil?

    verb, path, = request_line.split
    length = 0
    while (line = socket.gets) && line.strip != ''
      key, value = line.split(':', 2)
      length = value.to_i if key.to_s.downcase == 'content-length'
    end
    body = length.positive? ? socket.read(length) : ''
    request = Request.new(verb: verb, path: path, body: body)
    @requests << request

    status, payload = @handler.call(request)
    text = payload.is_a?(String) ? payload : JSON.generate(payload)
    socket.write("HTTP/1.1 #{status} #{status == 200 ? 'OK' : 'Error'}\r\n")
    socket.write("Content-Type: application/json\r\n")
    socket.write("Content-Length: #{text.bytesize}\r\n")
    socket.write("Connection: close\r\n\r\n")
    socket.write(text)
  end
end
