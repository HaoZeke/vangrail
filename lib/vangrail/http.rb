# frozen_string_literal: true

require 'json'
require 'net/http'
require 'uri'

module Vangrail
  # JSON over Net::HTTP with stdlib only: a guardrail that pulls in a transport
  # stack is a guardrail nobody installs. Every call is bounded by open and read
  # timeouts, because a rail that hangs is worse than a rail that is absent.
  class HTTP
    DEFAULT_OPEN_TIMEOUT = 5
    DEFAULT_READ_TIMEOUT = 30

    attr_reader :base_url, :open_timeout, :read_timeout, :retries

    def initialize(base_url:, api_key: nil, open_timeout: DEFAULT_OPEN_TIMEOUT,
                   read_timeout: DEFAULT_READ_TIMEOUT, retries: 1, headers: {})
      @base_url = base_url.to_s.sub(%r{/+\z}, '')
      raise ArgumentError, 'base_url is required' if @base_url.empty?

      @api_key = api_key
      @open_timeout = open_timeout
      @read_timeout = read_timeout
      @retries = retries
      @headers = headers
    end

    def get_json(path)
      request(Net::HTTP::Get, path, nil)
    end

    def post_json(path, payload)
      request(Net::HTTP::Post, path, payload)
    end

    # True when the endpoint answers at all. Used to pick a rail mode without
    # making the caller handle an exception for the ordinary "not running" case.
    def reachable?(path)
      get_json(path)
      true
    rescue HTTPError
      true
    rescue Error
      false
    end

    private

    def request(klass, path, payload)
      uri = URI.join("#{base_url}/", path.to_s.sub(%r{\A/+}, ''))
      attempt = 0
      begin
        attempt += 1
        perform(klass, uri, payload)
      rescue TransportError, HTTPError => e
        raise unless attempt <= retries && retryable?(e)

        sleep(0.25 * attempt)
        retry
      end
    end

    def retryable?(error)
      error.is_a?(TransportError) || error.retryable?
    end

    def perform(klass, uri, payload)
      req = klass.new(uri)
      req['Accept'] = 'application/json'
      req['Authorization'] = "Bearer #{@api_key}" if @api_key
      @headers.each { |k, v| req[k] = v }
      if payload
        req['Content-Type'] = 'application/json'
        req.body = JSON.generate(payload)
      end

      res = Net::HTTP.start(
        uri.hostname, uri.port,
        use_ssl: uri.scheme == 'https',
        open_timeout: open_timeout,
        read_timeout: read_timeout
      ) { |http| http.request(req) }

      code = res.code.to_i
      raise HTTPError.new(code, res.body) unless code.between?(200, 299)

      parse(res.body)
    rescue *transport_errors => e
      raise TransportError.new("#{uri.host}:#{uri.port} #{e.message}", cause_class: e.class.name)
    end

    def transport_errors
      [
        Errno::ECONNREFUSED, Errno::EHOSTUNREACH, Errno::ENETUNREACH, Errno::ECONNRESET,
        Net::OpenTimeout, Net::ReadTimeout, SocketError, IOError, EOFError
      ]
    end

    def parse(body)
      text = body.to_s
      return {} if text.strip.empty?

      JSON.parse(text)
    rescue JSON::ParserError => e
      raise ProtocolError, "endpoint returned non-JSON: #{e.message}"
    end
  end
end
