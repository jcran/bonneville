module Bonneville
  module Collector
    class Base
      include Sidekiq::Worker
      sidekiq_options :queue => "default", :backtrace => true

      include Intrigue::Task::Web

      # override me
      def perform(entity_id)
        @entity = Intrigue::Model::Entity.first(:id => entity_id)
      end

      private

      def _add_reference_data(item)
        $db.transaction do
          data = @entity.get_detail("reference_data") || []
          @entity.set_detail "reference_data", (data << item)
        end
      end

    end
  end
end
