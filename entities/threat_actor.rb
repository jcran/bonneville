module Bonneville
module Entity
class ThreatActor < Intrigue::Model::Entity

  def self.metadata
    {
      :name => "ThreatActor",
      :description => "This is a threat actor",
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
