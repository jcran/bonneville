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
        entities << tmp

      end

      # Write it out
      File.open("#{$intrigue_basedir}/public/export/#{prefix_name}#{result.name}.bonneville.clean.json", "w") do |file|
        file.write(entities.to_json)
      end
    end

  end
end
end
