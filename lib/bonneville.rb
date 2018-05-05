module Bonneville
  def version
    "0.1"
  end
end

### Scrapers
require_relative 'scraper/cisco_security'
require_relative 'scraper/generic'
require_relative 'scraper/ics_cert'
require_relative 'scraper/juniper_security'
require_relative 'scraper/security_focus'
require_relative 'scraper/security_tracker'

### Api
require_relative 'api/microsoft_security'
