module Bonneville
module Handler
  class BonnevilleCleanJson < Intrigue::Handler::Base

    def self.metadata
      {
        :name => "bonneville_clean_json",
        :pretty_name => "[bonneville] Export to Clean JSON file (/tmp)",
        :type => "export"
      }
    end

    def perform(result_type, result_id, prefix_name=nil)
      result = eval(result_type).first(id: result_id)
      return "Unable to process" unless result.respond_to? "export_json"

      # create a json_export_file (see core: lib/initialize/json_export_file.rb)
      j = JsonExportFile.new
      
      entities = []
      result.entities.each do |x|
        next unless x.kind_of? Bonneville::Entity::Cve

        # get the export hash
        tmp = x.export_hash

        # remove raw text
        if tmp[:details] && tmp[:details]["reference_data"]
          new_refs = tmp[:details]["reference_data"].map do |r|
            r["raw"] = nil
            r
          end
          tmp[:details]["reference_data"] = new_refs
        end

        # save it off
        j.store_entity tmp
      end


      j.write_and_close("#{$intrigue_basedir}/public/#{prefix_name}#{result.name}_clean.json")

    end

  end
end
end
