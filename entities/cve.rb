module Bonneville
module Entity
class Cve < Intrigue::Model::Entity

  def self.metadata
    {
      :name => "Cve",
      :description => "This is a CVE entry... Mitre Common Vulnerability Enumeration",
      :user_creatable => false
    }
  end

  def validate_entity
    name =~ /^cve-.*$/ #&&
      !details["description"].nil? &&
        details["references"].kind_of?(Array)
  end

  def enrichment_tasks
    ["enrich/cve"]
  end

  def detail_string
    details["references"].map{|r| r["type"] }.join(" | ") if details["references"]
  end

end
end
end
