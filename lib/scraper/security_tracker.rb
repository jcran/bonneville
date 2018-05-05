module Bonneville
  module Scraper
    class SecurityTracker

      include Intrigue::Task::Web

      def scrape(uri)
        body = http_get_body uri
        return nil unless body
        doc = Nokogiri::HTML body

        out = {}
        out["_raw"] = body

        desc = doc.xpath("//font")[40]
        out[:description] = desc.text.gsub("\n"," ").gsub("Description:","").strip if desc

        impact = doc.xpath("//font")[41]
        out[:impact] = impact.text.gsub("\n"," ").gsub("Impact:","").strip if impact

        solution = doc.xpath("//font")[42]
        out[:solution] = solution.text.gsub("\n"," ").gsub("Solution:","").strip if solution

      out
      end

    end
  end
end
