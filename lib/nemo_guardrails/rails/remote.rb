# frozen_string_literal: true

require_relative '../client'
require_relative '../rail'

module NemoGuardrails
  module Rails
    # A NeMo Guardrails server as one rail among the local ones.
    #
    # Wrapping the client in the rail protocol is what keeps the two paths from
    # becoming two designs. A team migrating off the Python service can put this
    # rail and a local one in the same ordered list, compare them on live
    # traffic, and drop the remote one when the local rails cover it.
    class Remote < Rail
      attr_reader :client

      def initialize(client: nil, base_url: nil, config_id: nil, api_key: nil,
                     name: 'remote', sides: Rail::SIDES)
        super(name: name, sides: sides)
        @client = client || Client.new(base_url: base_url, config_id: config_id, api_key: api_key)
      end

      def cache_key(text, context)
        return text if context[:side] == :input

        "#{context[:user_input]} #{text}"
      end

      def call(text, context)
        result =
          if context[:side] == :output
            client.check_output(text, user_input: context[:user_input])
          else
            client.check_input(text)
          end
        result.with_rail(name)
      end
    end
  end
end
