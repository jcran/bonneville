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
    cve_id = _get_entity_name
    refs = _get_entity_detail "references"
    eid = @entity.id

    unless refs
      _log_error "No References!"
    end

    refs.each do |ref|

      # Choose the right parser depending on the URI pattern
      if ref["url"] =~ /source.android.com/
      elsif ref["url"] =~ /support.apple.com/
      elsif ref["url"] =~ /ics-cert.us-cert.gov/
        _log "Got ICSCert Reference: #{ref["url"]}"
        Bonneville::Collector::IcsCert.perform_async(eid,ref["url"])
      elsif ref["url"] =~/chromium.org/
      elsif ref["url"] =~ /ciac.org/
      elsif ref["url"] =~ /cisecurity.org/
      elsif ref["url"] =~ /tools.cisco.com/
        _log "Got Cisco Reference: #{ref["url"]}"
        Bonneville::Collector::CiscoSecurity.perform_async(eid,ref["url"])
      elsif ref["url"] =~ /exploit-db.com/
      elsif ref["url"] =~ /fortigard/
      elsif ref["url"] =~ /www.ibm.com\/blogs\/psirt/
        _log "Got IBM Reference: #{ref["url"]}"
        Bonneville::Collector::IbmPsirt.perform_async(eid,ref["url"])
      elsif ref["url"] =~ /itrc.hp.com/
      elsif ref["url"] =~ /kb.juniper.net/
        _log "Got Juniper Reference: #{ref["url"]}"
        Bonneville::Collector::JuniperSecurity.perform_async(eid,ref["url"])
      elsif ref["url"] =~ /metasploit.com/
      elsif ref["url"] =~ /nodesecurity.io/
        _log "Got Node Security Reference: #{ref["url"]}"
        Bonneville::Collector::NodeSecurity.perform_async(eid,ref["url"])
      elsif ref["url"] =~ /lists.opensuse.org/
        # Skipping for now, multiple CVEs for a given reference. See:
        # https://lists.opensuse.org/opensuse-security-announce/2016-03/msg00047.html
      elsif ref["url"] =~ /osvdb.org/
      elsif ref["url"] =~ /portal.msrc.microsoft.com/
      elsif ref["url"] =~ /openwall.com/
      elsif ref["url"] =~ /oracle.com\/technetwork\/security-advisory/
      elsif ref["url"] =~ /access.redhat.com\/errata/

        # Fix and check the link
        # https://access.redhat.com/errata/RHSA-2016:1088
        # Bonneville::Collector::RedHatAccess.perform_async(eid,ref["url"])
        #red_hat_url = "https://bugzilla.redhat.com/show_bug.cgi?id=#{cve_id}"
        #Bonneville::Collector::RedHatBugzilla.perform_async(eid,red_hat_url)

      elsif ref["url"] =~ /bugzilla.redhat.com/

        # Test: https://bugzilla.redhat.com/show_bug.cgi?id=1387584 (cve-2016-10255)
        _log "Got Red Hat Reference: #{ref["url"]}"
        Bonneville::Collector::RedHatBugzilla.perform_async(eid,"#{ref["url"]}&ctype=xml")

      elsif ref["url"] =~ /rhn.redhat.com\/errata/

        # Fix and check the link
        # Test: http://rhn.redhat.com/errata/RHSA-2016-1089.html
        #rhid_components = "#{ref["url"]}".split("/").last.gsub(".html","").split("-")
        #rhid = "#{rhid_components[0]}-#{rhid_components[1]}:#{rhid_components[2]}"
        #redhat_uri = "https://access.redhat.com/errata/#{rhid}"
        #Bonneville::Collector::RedHatAccess.perform_async(eid,"#{redhat_uri}")

        # Check Bugzilla
        #red_hat_url = "https://bugzilla.redhat.com/show_bug.cgi?id=#{cve_id}"
        #Bonneville::Collector::RedHatBugzilla.perform_async(eid,red_hat_url)

      elsif ref["url"] =~ /secunia.com/
        _log "Got Secunia Reference: #{ref["url"]}"
        Bonneville::Collector::Secunia.perform_async(eid,ref["url"])
      elsif ref["url"] =~ /securitytracker.com/
        _log "Got Security Tracker Reference: #{ref["url"]}"
        Bonneville::Collector::SecurityTracker.perform_async(eid,ref["url"])
      elsif ref["url"] =~ /securityfocus.com/
        _log "Got Security Focus Reference: #{ref["url"]}"
        Bonneville::Collector::SecurityFocus.perform_async(eid,ref["url"])
      elsif ref["url"] =~ /sunsolve.sun.com/
        # https://lists.opensuse.org/opensuse-security-announce/2016-03/msg00047.html
      elsif ref["url"] =~ /patches.sgi.com/
      elsif ref["url"] =~ /exchange.xforce.ibmcloud.com/
      else
        _log "Unknown reference..."
      end

    end

    # always grab Xforce!
    Bonneville::Collector::XforceApi.perform_async(eid, cve_id)

  end

end
end
end
