module Bonneville
  module Api
    class Xforce

      include Intrigue::Task::Web

      def query(cve_id)
        _get_xforce_details(cve_id)
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

        return nil unless "#{ENV["XFORCE_AUTH"]}".length > 0

        # Query X-force for each
        # get the info from their api
        xforce_uri = "https://api.xforce.ibmcloud.com/vulnerabilities/search/#{cve_id.upcase}"

        headers = {
          content_type: :json,
          accept: :json,
          authorization: "#{ENV["XFORCE_AUTH"]}"
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
