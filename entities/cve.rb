module Bonneville
module Entity
class Cve < Intrigue::Model::Entity

  def self.metadata
    {
      :name => "Cve",
      :description => "This is a CVE entry... Mitre Common Vulnerability Enumeration",
      :user_creatable => true
    }
  end

  def validate_entity
    name =~ /^cve-.*$/i #&&
    #!details["description"].nil? &&
    #details["references"].kind_of?(Array)
  end

  def enrichment_tasks
    ["enrich/cve"]
  end

  def detail_string
    details["reference_data"].map{|r| r["source"] }.join(" | ") if details["reference_data"]
  end

end
end
end
