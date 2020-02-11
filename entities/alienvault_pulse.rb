module Bonneville
module Entity
class AlienvaultPulse < Intrigue::Model::Entity

  def self.metadata
    {
      :name => "AlienvaultPulse",
      :description => "This is an Alienvault OTX pulse which hast many referenceed threat entities",
      :user_creatable => true
    }
  end

  def validate_entity
    name =~ /\w+$/i 
  end

  def enrichment_tasks
    []
  end

end
end
end
