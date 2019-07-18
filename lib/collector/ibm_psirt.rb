Sidekiq::Queue['ibm_psirt'].limit = 1

module Bonneville
  module Collector
    class IbmPsirt < Bonneville::Collector::Base
      sidekiq_options :queue => "ibm_psirt", :backtrace => true

      def metadata
        {:source => "ibm_psirt" }
      end

      def perform(entity_id, uri)
        super entity_id

        body = http_get_body uri
        return nil unless body

        doc = Nokogiri::HTML body

        out = {}
        out[:description] = doc.xpath("//*[@id=\"ibm-content-main\"]/div/div[2]/div[1]/div[1]/p[4]").text

        _add_reference_data metadata.merge(out).merge(:uri => uri)
      end

    end
  end
end
