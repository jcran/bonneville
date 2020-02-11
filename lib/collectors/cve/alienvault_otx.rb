Sidekiq::Queue['alienvault_otx'].limit = 10

module Bonneville
  module Collector
    class AlienvaultOtx < Bonneville::Collector::Base
      sidekiq_options :queue => "alienvault_otx", :backtrace => true

      def metadata
        { :source => "alienvault_otx" }
      end

      def perform(entity_id, cve_id)
        super entity_id

        uri = "https://otx.alienvault.com/api/v1/indicators/cve/#{cve_id}/general"
        response = http_get_body(uri)
        begin
          
          # parse 
          out = JSON.parse(response)
          
          # remove references since it's double-up
          _add_reference_data metadata.merge(out.except("references")).merge(:uri => uri)

        rescue JSON::ParserError => e 
          _log_error "parser error!"    
          _add_reference_data metadata.merge(error: "invalid json").merge(uri: uri)
        end

      end
    end
  end
end
