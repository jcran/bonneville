Sidekiq::Queue['cisco_security'].limit = 1

module Bonneville
  module Collector
    class CiscoSecurity < Bonneville::Collector::Base
      sidekiq_options :queue => "cisco_security", :backtrace => true

      def metadata
        { :source => "cisco_security" }
      end

      def perform(entity_id, uri)
        super entity_id

        body  = http_get_body uri
        return nil unless body

        doc = Nokogiri::HTML body

        out = {}
        out[:raw] = body

        # Description
        description = doc.xpath("//*[@id=\"summaryfield\"]")
        out[:description] = description.text if description

        # CWE
        cwe = doc.xpath("//*[@id=\"advisorycontentheader\"]/div[1]/div[2]/div/div[6]/div/div[2]/div[1]/div")
        out[:cwe] = cwe.text if cwe

        _add_reference_data metadata.merge(out).merge(:uri => uri)

      end

    end
  end
end
