Sidekiq::Queue['node_security'].limit = 1

module Bonneville
  module Collector
    class NodeSecurity < Bonneville::Collector::Base
      sidekiq_options :queue => "node_security", :backtrace => true

      def metadata
        {:source => "node_security" }
      end

      def perform(entity_id, uri)
        super entity_id

        body = http_get_body uri
        return nil unless body

        doc = Nokogiri::HTML body

        out = {}
        out[:description] = doc.xpath("/html/body/div[2]/section[2]/div/p[1]").text

        _add_reference_data metadata.merge(out).merge(:uri => uri)
      end

    end
  end
end
