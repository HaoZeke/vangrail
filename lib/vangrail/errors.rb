# frozen_string_literal: true

module Vangrail
  # Base for everything this gem raises, so a caller can rescue one class.
  class Error < StandardError; end

  # The endpoint answered, but not with something this client understands.
  class ProtocolError < Error; end

  # Transport failed: connect refused, TLS, timeout, DNS.
  class TransportError < Error
    attr_reader :cause_class

    def initialize(message, cause_class: nil)
      super(message)
      @cause_class = cause_class
    end
  end

  # A 4xx or 5xx with the body kept for the operator.
  class HTTPError < Error
    attr_reader :status, :body

    def initialize(status, body)
      @status = status
      @body = body.to_s
      super("HTTP #{status}: #{@body[0, 400]}")
    end

    def retryable?
      status >= 500 || status == 429
    end
  end

  # No credential resolved for an endpoint that needs one.
  class MissingToken < Error; end

  # A Colang file used something outside the supported subset, or is malformed.
  # Raised at load, never at run: a rail configuration that half-loads would
  # report checks it is not performing.
  class ColangError < Error; end

  # A flow referred to an action or a bot message that nothing defines.
  class UnknownAction < ColangError; end

  # The configuration folder is missing something the rails it declares need.
  class ConfigError < Error; end
end
