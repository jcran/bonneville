module Bonneville
  module Scraper
    class SecurityFocus

      include Intrigue::Task::Web

      def scrape(uri)

        # get the discussion
        body  = http_get_body "#{uri.gsub("http:","https:")}/discuss"
        return nil unless body
        doc = Nokogiri::HTML body
        out = {}
        out["_raw"] = body

        # Seems like this is a combination of desciption, impact
        discussion = doc.xpath("//*[@id='vulnerability']")
        out[:discussion] = discussion.text.split("\n\t")[2] if discussion

      out
      end

    end
  end
end
