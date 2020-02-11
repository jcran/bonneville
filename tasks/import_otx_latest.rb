module Bonneville
module Task
class ImportAlienvaultOtxLatestPulses < Intrigue::Task::BaseTask

include Intrigue::Task::Generic
include Intrigue::Task::Web

  def self.metadata
    {
      :name => "import/otx_latest",
      :pretty_name => "Import Latest Pulses from Alienvault OTX",
      :authors => ["jcran"],
      :description => "This task downloads the latest pulses fom creates the related entities.",
      :references => [],
      :type => "import",
      :passive => true,
      :allowed_types => ["String"],
      :example_entities => [
        {"type" => "String", "details" => {"name" => "NA"} }
      ],
      :allowed_options => [],
      :created_types => ["AlienvaultPulse"]
    }
  end

  ## Default method, subclasses must override this
  def run
    super
    
    # Make sure the key is set
    api_key = _get_task_config("otx_api_key")

    headers ={
      Accept: 'application/json',
      'X-OTX-API-KEY': api_key
    }


    uri = "https://otx.alienvault.com/api/v1/pulses/subscribed?page=1"
    response = http_get_body(uri, headers)
    begin
      
      # parse 
      out = JSON.parse(response)
      
      puts out 

      #_create_entity "AlienvaultPulse", "name" 

    rescue JSON::ParserError => e 
      _log_error "parser error!"    
    end

  end

  private

=begin

        page_num = 1
        result = {"has_next" => true}

        while result["has_next"]
        
          # get the response, grab 50 at a time per alienvault docs
          response = http_get_body("#{url}?limit=50&page=#{page_num}", headers: headers)
          result = JSON.parse(response)
          
          # Parsd and create here
          # 
          # TODO
          #

          # increment and repeate
          page_num += 1
        end

      rescue JSON::ParserError => e
        _log_error "unable to parse json!"
      end

=end


end
end
end
