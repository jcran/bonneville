module Bonneville
module Entity
class ThreatGeography < Intrigue::Model::Entity

  def self.metadata
    {
      :name => "ThreatGeography",
      :description => "This is a source or target geography",
      :user_creatable => false
    }
  end

  def validate_entity # three letter code
    name =~ /[A-Z]{0,3}/i 
  end

  def enrichment_tasks
    []
  end

end
end
end
