module Bonneville
  def version
    "0.2"
  end
end

# dynamically load all collectors
require_relative 'collector/base'
cf = File.expand_path('../collector', __FILE__) # get absolute directory
Dir["#{cf}/*.rb"].each { |file| require_relative file }
