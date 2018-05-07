module Bonneville
module Handler
  class BonnevilleSimpleJson < Intrigue::Handler::Base

    def self.type
      "bonneville_simple_json"
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
        if tmp[:details] && tmp[:details]["references"]
          new_refs = tmp[:details]["references"].map do |ref|
            ref["data"]["_raw"] = nil if ref["data"]
            ref
          end
          #puts "New Refs: #{new_refs}"
          tmp[:details]["references"] = new_refs
        end

        # save it off
        entities << tmp

      end

      # Write it out
      File.open("#{$intrigue_basedir}/tmp/#{prefix_name}#{result.name}.bonneville_simple.json", "w") do |file|
        file.write(entities.to_json)
      end
    end

  end
end
end
