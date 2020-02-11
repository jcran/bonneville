Sidekiq::Queue['red_hat_bugzilla'].limit = 1

module Bonneville
  module Collector
    class RedHatBugzilla < Bonneville::Collector::Base
      sidekiq_options :queue => "red_hat_bugzilla", :backtrace => true

      def metadata
        {:source => "red_hat_bugzilla" }
      end

      def perform(entity_id, uri)
        super entity_id

        body = http_get_body uri
        return nil unless body

        doc = Nokogiri::XML body

        out = {}
        # this is the first comment
        out[:description] = doc.xpath("/bugzilla/bug/short_desc").text

        _add_reference_data metadata.merge(out).merge(:uri => uri)
      end

    end
  end
end
