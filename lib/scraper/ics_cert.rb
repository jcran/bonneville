module Bonneville
  module Scraper
    class IcsCert

      include Intrigue::Task::Web

      def scrape(uri)
        body = http_get_body uri
        return nil unless body
        doc = Nokogiri::HTML body

        out = {}

        advisory = doc.xpath("//*[@id='ncas-content']/div/div/div")
        out[:advisory] = advisory.text if advisory

      out
      end

    end
  end
end
