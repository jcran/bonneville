Sidekiq::Queue['security_focus'].limit = 1

module Bonneville
  module Collector
    class SecurityFocus < Bonneville::Collector::Base
      sidekiq_options :queue => "security_focus", :backtrace => true

      def metadata
        { :source => "security_focus" }
      end


      def perform(entity_id, uri)
        super entity_id
        # get the discussion
        body  = http_get_body "#{uri.gsub("http:","https:")}/discuss"
        return nil unless body
        doc = Nokogiri::HTML body
        out = {}
        out[:raw] = body
        # Seems like this is a combination of desciption, impact
        discussion = doc.xpath("//*[@id='vulnerability']")
        out[:description] = discussion.text.split("\n\t")[2] if discussion

        _add_reference_data metadata.merge(out).merge(:uri => uri)

      end

    end
  end
end
