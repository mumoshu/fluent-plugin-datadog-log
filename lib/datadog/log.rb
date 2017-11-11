require 'openssl'
require 'net/tcp_client'
require 'socket'
require 'time'

module Datadog
  module Log
    TRUNCATED_MSG = '...TRUNCATED...'

    TRUNCATED_LEN = TRUNCATED_MSG.size

    # MaxMessageLen is the maximum length for any message we send to the intake
    # see https://github.com/DataDog/datadog-log-agent/blob/2394da8c79a6cadbcd1e98d6c89c437becec2732/pkg/config/constants.go#L9-L10
    DD_MAX_MESSAGE_LEN = 1 * 1000 * 1000

    MAX_MESSAGE_LEN = DD_MAX_MESSAGE_LEN - TRUNCATED_LEN

    def truncate_message(msg)
      if msg.size > DD_MAX_MESSAGE_LEN
        msg.slice(0, MAX_MESSAGE_LEN) + TRUNCATED_MSG
      else
        msg
      end
    end

    # Given a list of tags, build_tags_payload generates the bytes array
    # that will be inserted into messages
    # @see https://github.com/DataDog/datadog-log-agent/blob/2394da8c79a6cadbcd1e98d6c89c437becec2732/pkg/config/integration_config.go#L180
    def build_tags_payload(config_tags:, source:, source_category:)
      payload = ''

      payload = "[dd ddsource=\"#{source}\"]" if !source.nil? && source != ''

      if !source_category.nil? && source_category != ''
        payload = "#{payload}[dd ddsourcecategory=\"#{source_category}\"]"
      end

      if !config_tags.nil? && config_tags != ''
        config_tags = config_tags.join(',') if config_tags.is_a? ::Array
        payload = "#{payload}[dd ddtags=\"#{config_tags}\"]"
      end

      payload
    end

    # https://github.com/DataDog/datadog-log-agent/blob/db13b53dfdd036d43acfb15089a43eb31548f09f/pkg/processor/processor.go#L65
    def build_extra_content(timestamp:, hostname:, service:, tags_payload:)
      "<46>0 #{timestamp} #{hostname} #{service} - - #{tags_payload}"
    end

    def build_api_key_str(api_key:, logset:)
      if !logset.nil? && logset != ''
        "#{api_key}/#{logset}"
      else
        api_key
      end
    end

    # build_payload returns a processed payload from a raw message
    # @param [String] api_key_str
    # @param [String] extra_content
    # @param [String] msg
    def create_payload(api_key_str:, msg:, extra_content:)
      "#{api_key_str} #{extra_content} #{msg}\n"
    end

    class Client
      include ::Datadog::Log

      def initialize(log_dd_url: 'intake.logs.datadoghq.com', log_dd_port: 10516, api_key:, hostname:, skip_ssl_validation: false)
        @log_dd_url = log_dd_url
        @log_dd_port = log_dd_port
        @api_key = api_key
        @hostname = hostname
        @skip_ssl_validation = skip_ssl_validation

        init_api_client
      end

      def send_payload(logset: 'main', msg:, datetime: nil, service:, source:, source_category:, tags:)
        datetime = DateTime.now if datetime.nil?

        # new_offset(0) is required. otherwise datadog will silently throws away the log..
        timestamp_str = datetime.new_offset(0).rfc3339(6)
        payload = create_payload(
          api_key_str: build_api_key_str(api_key: @api_key, logset: logset),
          msg: truncate_message(msg),
          extra_content: build_extra_content(
            timestamp: timestamp_str,
            hostname: @hostname,
            service: service,
            tags_payload: build_tags_payload(
              config_tags: tags,
              source: source,
              source_category: source_category
            )
          )
        )
        @conn.write(payload)
        payload
      end

      def shutdown
        @conn.close unless @conn.nil?
      end

      class << self
        def from_env
          new(api_key: ENV['DD_LOG_API_KEY'], hostname: Socket.gethostname)
        end
      end

      private

      def init_api_client
        ssl = true
        ssl = { verify_mode: OpenSSL::SSL::VERIFY_NONE } if @skip_ssl_validation
        server = "#{@log_dd_url}:#{@log_dd_port}"
        @conn = Net::TCPClient.new(server: server, ssl: ssl)
      end
    end
  end
end
