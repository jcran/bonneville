module Bonneville
  def version
    "0.3"
  end
end

require_relative 'helpers'

# dynamically load all collectors
require_relative 'collectors/base'
cf = File.expand_path('../collectors', __FILE__) # get absolute directory
Dir["#{cf}/*.rb"].each { |file| require_relative file }
