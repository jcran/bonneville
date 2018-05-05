module Bonneville
module Task
class ImportNvdJson < Intrigue::Task::BaseTask

include Intrigue::Task::Generic
include Intrigue::Task::Web

def self.metadata
  {
    :name => "import/nvd_json",
    :pretty_name => "Import CVEs from NVD (JSON)",
    :authors => ["jcran", "jayjacobs"],
    :description => "This task download the nvd json and creates cve entities.",
    :references => [],
    :type => "import",
    :passive => true,
    :allowed_types => ["String"],
    :example_entities => [
      {"type" => "String", "details" => {"name" => "modified"} }
    ],
    :allowed_options => [
      {:name => "max_items", :regex => "integer", :default => 1000000 },
    ],
    :created_types => ["Cve"]
  }
end

## Default method, subclasses must override this
def run
  super

  files = []
  year_filter = _get_entity_name

  if year_filter == "recent"

    f = download_and_store "https://nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-recent.json.gz", ["nvdcve-1.0-recent",".json.gz"]
    _log `gunzip #{f}`
    files = [f.gsub(".gz","")]

  elsif year_filter == "modified"

    f = download_and_store "https://nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-modified.json.gz", ["nvdcve-1.0-modified",".json.gz"]
    _log `gunzip #{f}`
    files = [f.gsub(".gz","")]

  elsif year_filter == "all"

    years = ["2018","2017","2016","2015","2014","2013","2012","2011","2010","2009","2008","2007","2006","2005","2004","2003","2002","2001","2000","1999"]
    years.each do |y|
      filename = "https://nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-#{y}.json.gz"
      f = download_and_store filename, ["nvdcve-1.0-#{y}",".json.gz"]
      _log `gunzip #{f}`
      files << f.gsub(".gz","")
    end

  else

    years = year_filter.split(",")
    years.each do |y|
      filename = "https://nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-#{y}.json.gz"
      f = download_and_store filename, ["nvdcve-1.0-#{y}",".json.gz"]
      _log `gunzip #{f}`
      files << f.gsub(".gz","")
    end

  end

  files.each do |f|
    _log "Parsing file: #{f}"
  end

  files.each do |f|
    j = JSON.parse(File.open(f,"r").read)

    max_items = _get_option("max_items")
    cve_entry = j["CVE_Items"][0..max_items].each do |cve_entry|

      cve_id = cve_entry["cve"]["CVE_data_meta"]["ID"]
      cve_assigner = cve_entry["cve"]["CVE_data_meta"]["ASSIGNER"]
      cwe_id = _get_cwe_id(cve_entry)
      references = _get_references(cve_entry)
      description = _get_description(cve_entry)

      _create_entity "Cve", {
        "name" => cve_id,
        "assigner" => cve_assigner,
        "cwe_id" => cwe_id,
        "description" => description,
        "references" => references
      }

    end
  end
end

private
def _get_cwe_id(cve_entry)
  begin
    return cve_entry["cve"]["problemtype"]["problemtype_data"].first["description"].first["value"]
  rescue NoMethodError => e
    _log_error "Unable to get CWE for #{cve_entry}: #{e}"
  end
nil
end

def _get_references(cve_entry)
  begin
    return cve_entry["cve"]["references"]["reference_data"]
  rescue NoMethodError => e
    _log_error "Unable to get references for #{cve_entry}: #{e}"
  end
nil
end

def _get_description(cve_entry)
  begin
    return cve_entry["cve"]["description"]["description_data"].first["value"]
  rescue NoMethodError => e
    _log_error "Unable to get description for #{cve_entry}: #{e}"
  end
nil
end


end
end
end
