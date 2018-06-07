Sidekiq::Queue['red_hat_access'].limit = 1

module Bonneville
  module Collector
    class RedHatAccess < Bonneville::Collector::Base
      sidekiq_options :queue => "red_hat_access", :backtrace => true

      def metadata
        {:source => "red_hat_access" }
      end

      def perform(entity_id, uri)
        super entity_id

        body = http_get_body uri
        return nil unless body

        doc = Nokogiri::HTML body

        out = {}
        out[:description] = doc.xpath("//*[@id="overview"]").text

        _add_reference_data metadata.merge(out).merge(:uri => uri)
      end

    end
  end
end
