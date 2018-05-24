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
    refs = _get_entity_detail "references"

    unless refs
      _log_error "No References!!!"
    end

    refs.map! do |ref|

      # Choose the right parser depending on the URI pattern
      if ref["url"] =~ /source.android.com/
        ref["type"] = "android"
        # TODO - android » api/scrape

      elsif ref["url"] =~ /support.apple.com/
        ref["type"] = "apple"
        # TODO - apple api/scrape

      elsif ref["url"] =~ /ics-cert.us-cert.gov/
        ref["type"] = "ics_cert"
        ref["data"] = Bonneville::Scraper::IcsCert.new.scrape(ref["url"])

      elsif ref["url"] =~/chromium.org/
        ref["type"] = "chromium"

      elsif ref["url"] =~ /ciac.org/
        ref["type"] = "ciac"
        # TODO - ciac

      elsif ref["url"] =~ /cisecurity.org/
        ref["type"] = "cisecurity.org"
        # TODO - cisecurity.org

      elsif ref["url"] =~/tools.cisco.com/
        ref["type"] = "cisco_security"
        ref["data"] = Bonneville::Scraper::CiscoSecurity.new.scrape(ref["url"])

      elsif ref["url"] =~ /exploit-db.com/
        ref["type"] = "exploit_db"
        # TODO - exploitdb api/scrape

      elsif ref["url"] =~ /fortigard/
        ref["type"] = "fortigard"
        # TODO - fortigard api/scrape

      elsif ref["url"] =~ /itrc.hp.com/
        ref["type"] = "itrc.hp.com"
        # TODO - HP api/scrape


      elsif ref["url"] =~ /kb.juniper.net/
        ref["type"] = "juniper_security"
        ref["data"] = Bonneville::Scraper::JuniperSecurity.new.scrape(ref["url"])

      elsif ref["url"] =~ /metasploit.com/
        ref["type"] = "metasploit"
        # TODO - metasploit api/scrape

      elsif ref["url"] =~ /osvdb.org/
        ref["type"] = ""
        # TODO - osvdb

      elsif ref["url"] =~ /portal.msrc.microsoft.com/
        ref["type"] = "microsoft_security"
        # TODO - microsoft api/scrape

      elsif ref["url"] =~ /openwall.com/
        ref["type"] = "openwall"
        # TODO - openwall mailing list api/scrape

      elsif ref["url"] =~ /oracle.com\/technetwork\/security-advisory/
        ref["type"] = "oracle"
        # TODO - oracle api/scrape

      elsif ref["url"] =~ /bugzilla.redhat.com/
        ref["type"] = "red_hat"
        # TODO - redhat api/scrape

      elsif ref["url"] =~ /securitytracker.com/
        ref["type"] = "security_tracker"
        ref["data"] = Bonneville::Scraper::SecurityTracker.new.scrape(ref["url"])

      elsif ref["url"] =~ /securityfocus.com/
        ref["type"] = "security_focus"
        ref["data"] = Bonneville::Scraper::SecurityFocus.new.scrape(ref["url"])

      elsif ref["url"] =~ /sunsolve.sun.com/
        ref["type"] = "sun.com"
        # TODO - sun.com

      elsif ref["url"] =~ /patches.sgi.com/
        ref["type"] = "sgi"
        # TODO - sgi

      elsif ref["url"] =~ /exchange.xforce.ibmcloud.com/
        ref["type"] = "xforce"
        ref["data"] = Bonneville::Api::Xforce.new.query(_get_entity_name)

      end

      ref["data"] = Bonneville::Scraper::Generic.new.scrape(ref["url"])
      ref["type"] = "unknown_reference"
      ref
    end

    # save us up
    @entity.set_detail("references", refs)

    _finalize_enrichment
  end

end
end
end
