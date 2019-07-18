Sidekiq::Queue['ics_cert'].limit = 1

module Bonneville
  module Collector
    class IcsCert < Bonneville::Collector::Base
      sidekiq_options :queue => "ics_cert", :backtrace => true

      def metadata
        {:source => "ics_cert" }
      end

      def perform(entity_id, uri)
      super entity_id

        body = http_get_body uri
        return nil unless body
        doc = Nokogiri::HTML body

        out = {}
        out[:raw] = body

        advisory = doc.xpath("//*[@id='ncas-content']/div/div/div")
        out[:description] = advisory.text if advisory

        _add_reference_data metadata.merge(out).merge(:uri => uri)
      end

    end
  end
end
