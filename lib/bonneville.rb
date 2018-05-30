module Bonneville
  def version
    "0.2"
  end
end

require_relative 'collector/base'
require_relative 'collector/cisco_security'
require_relative 'collector/generic_html'
require_relative 'collector/ics_cert'
require_relative 'collector/juniper_security'
require_relative 'collector/security_focus'
require_relative 'collector/security_tracker'
require_relative 'collector/microsoft_security'
require_relative 'collector/xforce'
