Sidekiq::Queue['generic_html'].limit = 5

module Bonneville
  module Collector
    class Secunia < Bonneville::Collector::Base
      sidekiq_options :queue => "secunia", :backtrace => true

      def metadata
        {:source => "secunia" }
      end

      def perform(entity_id, uri)
        super entity_id

        body = http_get_body uri
        return nil unless body

        doc = Nokogiri::HTML body

        out = {}
        out[:description] = doc.xpath("/html/body/div[1]/div/div[6]/div/div/div[2]/div/p").text

        _add_reference_data metadata.merge(out).merge(:uri => uri)
      end

    end
  end
end
