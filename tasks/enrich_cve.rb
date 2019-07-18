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
      :allowed_options => [
        {:name => "check_nvd_references", :regex=> "boolean", :default => false },
        {:name => "check_xforce", :regex=> "boolean", :default => false },
        {:name => "check_alienvault_otx", :regex=> "boolean", :default => true },
        {:name => "check_symantec_attack_sigs", :regex=> "boolean", :default => false }
      ],
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

    if _get_option "check_nvd_references"
      
      unless refs
        
        _log "No References available, skipping NVD reference checks!"

      else

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

        end # end references iteration

      end # we had refs

    end # end check_references

    ## ALWAYS run these if they're configured 

    if _get_option "check_xforce"
      # grab Xforce for each cve
      Bonneville::Collector::XforceApi.perform_async(eid, cve_id)
    end

    if _get_option "check_alienvault_otx"
      # grab OTX for each cve!
      Bonneville::Collector::AlienvaultOtx.perform_async(eid, cve_id)
    end

    if _get_option "check_symantec_attack_sigs"

        #
        # feels hacky to do this here, but it's a set-once kinda thing 
        # (we don't want to scrape unless we have to... )
        #
        unless $symantec_attack_sig_map
          $symantec_attack_sig_map = {}
          map_uri = "https://www.symantec.com/security_response/attacksignatures/"
          body = http_get_body(map_uri);nil
          doc = Nokogiri::HTML(body);nil
          sig_nodes = doc.xpath("/html[1]/body[1]/div[3]/div[2]/div[1]/div[2]/a");nil
          
          sig_nodes.each do |node| 
            cve_match = node.text.match(/(CVE-\d+-\d+)\s/)
            next unless cve_match
            cve_id = cve_match.captures.first
            cve_link = "https://www.symantec.com#{node.attribute("href").value}"
            $symantec_attack_sig_map[cve_id] = [] unless $symantec_attack_sig_map[cve_id]
            $symantec_attack_sig_map[cve_id] << cve_link
          end;nil
        end

      # grab it for each cve!
      Bonneville::Collector::SymantecAttackSigs.perform_async(eid, cve_id)
    end




  end

end
end
end
