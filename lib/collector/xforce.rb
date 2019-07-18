Sidekiq::Queue['xforce_api'].limit = 2

module Bonneville
  module Collector
    class XforceApi < Bonneville::Collector::Base
      sidekiq_options :queue => "xforce_api", :backtrace => true

      def metadata
        { :source => "xforce_api" }
      end

      def perform(entity_id, cve_id)
        super entity_id

        #raise "Xforce API key missing!" unless "#{ENV["XFORCE_API_KEY"]}".length > 0
        unless "#{ENV["XFORCE_API_KEY"]}".length > 0
          puts "ERROR MISSING XFORCE KEY"
          return
        end

        out = _get_xforce_details(cve_id).first

        desc = out["description"] if out.kind_of? Hash

        _add_reference_data metadata.merge({
          :description => desc,
          :raw => out,
          :uri => "https://api.xforce.ibmcloud.com/vulnerabilities/search/#{cve_id.upcase}"
        })

      end

      private
      # Hits XForce database for data and returns all data
      #
      # 2.0 test value -  cve_id = "CVE-2014-0964" # (xfdbid = 92877)
      # 3.0 test value -  cve_id = "CVE-2018-0101"
      #
      # @param cve_id [String] the cve id, like CVE-YYYY-XXXX
      # @return [Hash] full xforce data
      def _get_xforce_details(cve_id)

        # Query X-force for each
        # get the info from their api
        xforce_uri = "https://api.xforce.ibmcloud.com/vulnerabilities/search/#{cve_id.upcase}"

        headers = {
          content_type: :json,
          accept: :json,
          authorization: "#{ENV["XFORCE_API_KEY"]}"
        }

        begin
          # Get our Xforce data
          creds = nil
          response = http_request :get, "#{xforce_uri}", creds, headers
          details = JSON.parse(response.body)
        rescue JSON::ParserError => e
          puts "Parsing Error: #{e}"
        end

      details
      end

    end
  end
end
