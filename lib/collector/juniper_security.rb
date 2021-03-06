Sidekiq::Queue['juniper_security'].limit = 1

module Bonneville
  module Collector
    class JuniperSecurity < Bonneville::Collector::Base
      sidekiq_options :queue => "juniper_security", :backtrace => true

      def metadata
        { :source => "juniper_security" }
      end

      def perform(entity_id, uri)
        super entity_id

        body  = http_get_body uri
        return nil unless body

        doc = Nokogiri::HTML body

        out = {}
        out[:raw] = body

        problem = doc.xpath("//*[@id='moduleAppMain']/div/div/div[4]/div[2]")
        out[:description] = problem.text if problem

        # Parse CVSS since we're in the neighborhood
        cvss_string = doc.xpath("//*[@id='moduleAppMain']/div/div/div[4]/div[11]")
        clean_cvss_string = cvss_string.text.gsub("\n\t","") if cvss_string

        if clean_cvss_string
          # Parse out the CVSS Score
          score = clean_cvss_string.scan(/^\s+([0-9]\.[0-9]).*$/)[0]
          out[:cvss_score] = score.first if score

          # Parse out the CVSS Version
          version = clean_cvss_string.scan(/^.*([0-9]\.[0-9]).*$/)[0]
          out[:cvss_version] = version.first if version

          # Parse out the CVSS Vector
          vector = clean_cvss_string.scan(/^.*\(CVSS:3.0\/(.*)\)$/)[0]
          out[:cvss_vector] = vector.first if vector
        end

        _add_reference_data metadata.merge(out).merge(:uri => uri)
      end

    end
  end
end
