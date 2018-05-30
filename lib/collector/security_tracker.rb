Sidekiq::Queue['security_tracker'].limit = 1

module Bonneville
  module Collector
    class SecurityTracker < Bonneville::Collector::Base
      sidekiq_options :queue => "security_tracker", :backtrace => true

      def metadata
        { :source => "security_tracker" }
      end

      def perform(entity_id, uri)
        super entity_id

        body = http_get_body uri
        return nil unless body

        doc = Nokogiri::HTML body

        out = {}
        out[:raw] = body

        desc = doc.xpath("//font")[40]
        out[:description] = desc.text.gsub("\n"," ").gsub("Description:","").strip if desc

        impact = doc.xpath("//font")[41]
        out[:impact] = impact.text.gsub("\n"," ").gsub("Impact:","").strip if impact

        solution = doc.xpath("//font")[42]
        out[:solution] = solution.text.gsub("\n"," ").gsub("Solution:","").strip if solution

        _add_reference_data metadata.merge(out).merge(:uri => uri)
      end

    end
  end
end
