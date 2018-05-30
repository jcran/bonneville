Sidekiq::Queue['microsoft_security_api'].limit = 1

module Bonneville
  module Collector
    class MicrosoftSecurityApi < Bonneville::Collector::Base
      sidekiq_options :queue => "microsoft_security_api", :backtrace => true

      def metadata
        {:name => "microsoft_security_api" }
      end

      def perform(entity_id, uri)
        super entity_id
        raise "not yet implemented"
      end

    end
  end
end
