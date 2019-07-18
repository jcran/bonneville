Sidekiq::Queue['generic_html'].limit = 5

module Bonneville
  module Collector
    class GenericHtml < Bonneville::Collector::Base
      sidekiq_options :queue => "generic_html", :backtrace => true

      def metadata
        {:source => "generic_html" }
      end

      def perform(entity_id, uri)
        super entity_id

        body = http_get_body uri
        return nil unless body
        doc = Nokogiri::HTML body

        out = {}
        out[:raw] = body

        _add_reference_data metadata.merge(out).merge(:uri => uri)
      end

    end
  end
end
