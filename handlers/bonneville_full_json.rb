module Bonneville
module Handler
  class BonnevilleFullJson < Intrigue::Handler::Base

    def self.metadata
      {
        :name => "bonneville_full_json",
        :pretty_name => "[bonneville] Export to Full JSON file",
        :type => "export"
      }
    end

    def perform(result_type, result_id, prefix_name=nil)
      result = eval(result_type).first(id: result_id)
      return "Unable to process" unless result.respond_to? "export_json"

      # create a json_export_file (see core: lib/initialize/json_export_file.rb)
      j = JsonExportFile.new("#{$intrigue_basedir}/public/#{prefix_name}#{result.name}_full.json")

      entities = []
      result.entities.each do |x|
        next unless x.kind_of? Bonneville::Entity::Cve

        # get the export hash & save it off
        j.store_entity x.export_hash
      end

      j.write_and_close

    end

  end
end
end
