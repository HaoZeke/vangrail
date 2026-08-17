# frozen_string_literal: true

require 'json'
require 'socket'
require_relative 'errors'
require_relative 'front'
require_relative 'version'

module Vangrail
  # Loopback HTTP for step 2: other languages call this process, they do not
  # embed MRI. One connection at a time, stdlib only, same JSON as Front.
  class Server
    MAX_BODY = 4 * 1024 * 1024

    ROUTES = {
      '/v1/check_input' => 'check_input',
      '/v1/check_output' => 'check_output',
      '/v1/check_context' => 'check_context',
      '/v1/screen' => 'screen',
      '/v1/assess' => 'assess',
    }.freeze

    attr_reader :front, :host, :port

    def initialize(front:, host: '127.0.0.1', port: 0)
      @front = front
      @host = host
      @port = port
      @server = TCPServer.new(host, port)
      @port = @server.addr[1]
    end

    def base_url
      "http://#{host}:#{port}"
    end

    def start
      @thread = Thread.new { accept_loop }
      @thread.abort_on_exception = false
      self
    end

    def close
      @closing = true
      @server.close unless @server.closed?
      @thread&.kill
    end

    def self.with(front:, **kwargs)
      server = new(front: front, **kwargs).start
      begin
        yield server
      ensure
        server.close
      end
    end

    private

    def accept_loop
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
      path = path.to_s.split('?', 2).first
      length = 0
      while (line = socket.gets) && line.strip != ''
        key, value = line.split(':', 2)
        length = value.to_i if key.to_s.downcase == 'content-length'
      end
      if length > MAX_BODY
        text = JSON.generate('error' => 'body too large')
        socket.write("HTTP/1.1 413 Payload Too Large\r\n")
        socket.write("Content-Type: application/json\r\n")
        socket.write("Content-Length: #{text.bytesize}\r\n")
        socket.write("Connection: close\r\n\r\n")
        socket.write(text)
        return
      end
      body = length.positive? ? socket.read(length) : ''
      status, payload = respond(verb, path, body)
      text = JSON.generate(payload)
      socket.write("HTTP/1.1 #{status} #{reason_phrase(status)}\r\n")
      socket.write("Content-Type: application/json\r\n")
      socket.write("Content-Length: #{text.bytesize}\r\n")
      verdict_headers(payload).each { |key, value| socket.write("#{key}: #{value}\r\n") }
      socket.write("Connection: close\r\n\r\n")
      socket.write(text)
    end

    def respond(verb, path, body)
      return [200, { 'ok' => true, 'version' => VERSION }] if verb == 'GET' && path == '/v1/health'
      return [405, { 'error' => 'method not allowed' }] unless verb == 'POST'

      command = ROUTES[path]
      return [404, { 'error' => "unknown path #{path}" }] unless command

      [200, front.dispatch(command, parse_body(body))]
    rescue ArgumentError, Error => e
      [400, { 'error' => e.message }]
    rescue JSON::ParserError => e
      [400, { 'error' => "invalid JSON: #{e.message}" }]
    end

    def parse_body(body)
      raise ArgumentError, 'body too large' if body.to_s.bytesize > MAX_BODY

      body.to_s.strip.empty? ? {} : JSON.parse(body)
    end

    def verdict_headers(payload)
      headers = {}
      if payload['status']
        headers['X-Vangrail-Status'] = payload['status'].to_s
        headers['X-Vangrail-Certain'] = payload.fetch('certain', true).to_s
      elsif payload.key?('certain')
        headers['X-Vangrail-Status'] = 'screen'
        headers['X-Vangrail-Certain'] = payload['certain'].to_s
      end
      headers
    end

    def reason_phrase(status)
      { 200 => 'OK', 400 => 'Bad Request', 404 => 'Not Found', 405 => 'Method Not Allowed' }[status] || 'Error'
    end
  end
end
