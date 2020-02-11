Sidekiq::Queue['symantec_attack_sigs'].limit = 1

module Bonneville
  module Collector
    class SymantecAttackSigs < Bonneville::Collector::Base
      sidekiq_options :queue => "symantec_attack_sigs", :backtrace => true

      def metadata
        { :source => "symantec_attack_sigs" }
      end

      def perform(entity_id, cve_id)
        super entity_id

        if $symantec_attack_sig_map[cve_id]
          $symantec_attack_sig_map[cve_id].each do |cve_link|
                        
            cve_body = http_get_body(cve_link);nil
            cve_doc = Nokogiri::HTML(cve_body);nil

            description = cve_doc.xpath("/html[1]/body[1]/div[3]/div[2]/div[1]/div[1]").text
            additional = cve_doc.xpath("/html[1]/body[1]/div[3]/div[2]/div[1]/div[2]").text
            
            out = {
              uri: cve_link, 
              description: description.gsub("Description\n","").strip, 
              additional: additional.gsub("Additional Information\n","").strip
            }

            _add_reference_data(metadata.merge(out).merge(uri: cve_link))
          end
        else
          _add_reference_data(metadata.merge(found: false))
        end

      end
    end
  end
end
