module Bonneville
  def version
    "0.2"
  end
end

require_relative 'helpers'

# dynamically load all collectors
require_relative 'collector/base'
cf = File.expand_path('../collector', __FILE__) # get absolute directory
Dir["#{cf}/*.rb"].each { |file| require_relative file }
