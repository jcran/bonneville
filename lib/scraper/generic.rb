module Bonneville
  module Scraper
    class Generic

      include Intrigue::Task::Web

      def scrape(uri)
        body = http_get_body uri
        return nil unless body
        doc = Nokogiri::HTML body
        out = {}
        out["_raw"] = body

      out
      end

    end
  end
end
