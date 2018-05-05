require_relative '../lib/bonneville'

module Bonneville
module Task
class EnrichCve < Intrigue::Task::BaseTask

  def self.metadata
    {
      :name => "enrich/cve",
      :pretty_name => "Enrich a CVE",
      :authors => ["jcran"],
      :description => "",
      :references => [],
      :allowed_types => ["Cve"],
      :type => "enrichment",
      :passive => true,
      :example_entities => [
        {"type" => "Cve", "details" => {"name" => "CVE-2018-0101"} }
      ],
      :allowed_options => [],
      :created_types => []
    }
  end

  def run
    super

    # Go grab the References
    #
    refs = @entity.get_detail "references"

    unless refs
      _log_error "No References!!!"
    end

    refs.map! do |ref|

      # Choose the right parser depending on the URI pattern
      if ref["url"] =~ /ics-cert.us-cert.gov/
        ref["type"] = "ics_cert"
        ref["scraped"] = Bonneville::Scraper::IcsCert.new.scrape(ref["url"])

      elsif ref["url"] =~/tools.cisco.com/
        ref["type"] = "cisco_security"
        ref["scraped"] = Bonneville::Scraper::CiscoSecurity.new.scrape(ref["url"])

      elsif ref["url"] =~/kb.juniper.net/
        ref["type"] = "juniper_security"
        ref["scraped"] = Bonneville::Scraper::JuniperSecurity.new.scrape(ref["url"])

      elsif ref["uri"] =~ /portal.msrc.microsoft.com/
        ref["type"] = "microsoft_security"
        # TODO - build an API client, scraping hits

      elsif ref["url"] =~ /securitytracker.com/
        ref["type"] = "security_tracker"
        ref["scraped"] = Bonneville::Scraper::SecurityTracker.new.scrape(ref["url"])

      elsif ref["uri"] =~ /www.securityfocus.com/
        ref["type"] = "security_focus"
        uri = ref["url"].gsub("http:","https:") + "/discuss" # Fixup the correct uri
        ref["scraped"] = Bonneville::Scraper::SecurityFocus.new.scrape(uri)
      end

    ref
    end

    # save us up
    @entity.set_detail("references", refs)

    _finalize_enrichment
  end

end
end
end
