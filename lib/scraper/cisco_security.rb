module Bonneville
  module Scraper
    class CiscoSecurity

      include Intrigue::Task::Web

      def scrape(uri)

        body  = http_get_body uri
        return nil unless body

        doc = Nokogiri::HTML body

        out = {}

        # Description
        description = doc.xpath("//*[@id=\"summaryfield\"]")
        out[:description] = description.text if description

        # CWE
        cwe = doc.xpath("//*[@id=\"advisorycontentheader\"]/div[1]/div[2]/div/div[6]/div/div[2]/div[1]/div")
        out[:cwe] = cwe.text if cwe

      out
      end

    end
  end
end
