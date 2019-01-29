module Bonneville
module Handler
  class BonnevilleFullJson < Intrigue::Handler::Base

    def self.metadata
      {
        :name => "bonneville_full_json",
        :pretty_name => "[bonneville] Export to Full JSON file (/tmp)",
        :type => "export"
      }
    end

    def perform(result_type, result_id, prefix_name=nil)
      result = eval(result_type).first(id: result_id)
      return "Unable to process" unless result.respond_to? "export_json"

      entities = []
      result.entities.each do |x|
        next unless x.kind_of? Bonneville::Entity::Cve

        # get the export hash & save it off
        entities << x.export_hash

      end

      # Write it out
      File.open("#{$intrigue_basedir}/public/export/#{prefix_name}#{result.name}.bonneville.full.json", "w") do |file|
        file.write(entities.to_json)
      end

    end

  end
end
end
