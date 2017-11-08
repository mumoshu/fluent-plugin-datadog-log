# Copyright 2017 Yusuke KUOKA All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
require 'erb'
require 'json'
require 'open-uri'
require 'socket'
require 'time'
require 'yaml'
require 'net/tcp_client'
require 'fluent/plugin/output'

require_relative 'monitoring'

module Fluent::Plugin
  # fluentd output plugin for the Datadog Log Intake API
  class DatadogOutput < ::Fluent::Plugin::Output
    Fluent::Plugin.register_output('datadog', self)

    helpers :compat_parameters, :inject

    DEFAULT_BUFFER_TYPE = 'memory'

    PLUGIN_NAME = 'Fluentd Datadog plugin'
    PLUGIN_VERSION = '0.1.0'

    # Address of the metadata service.
    METADATA_SERVICE_ADDR = '169.254.169.254'

    # Disable this warning to conform to fluentd config_param conventions.
    # rubocop:disable Style/HashSyntax

    TRUNCATED_MSG = '...TRUNCATED...'

    TRUNCATED_LEN = TRUNCATED_MSG.size

    # MaxMessageLen is the maximum length for any message we send to the intake
    # see https://github.com/DataDog/datadog-log-agent/blob/2394da8c79a6cadbcd1e98d6c89c437becec2732/pkg/config/constants.go#L9-L10
    DD_MAX_MESSAGE_LEN = 1 * 1000 * 1000

    MAX_MESSAGE_LEN = DD_MAX_MESSAGE_LEN - TRUNCATED_LEN

    # see https://github.com/DataDog/datadog-log-agent/blob/db13b53dfdd036d43acfb15089a43eb31548f09f/pkg/logagent/logsagent.go#L26-L30
    # see https://github.com/DataDog/datadog-log-agent/blob/db13b53dfdd036d43acfb15089a43eb31548f09f/pkg/config/config.go#L52-L56
    config_param :log_dd_url, :string, default: 'intake.logs.datadoghq.com'
    config_param :log_dd_port, :integer, default: 10516
    config_param :skip_ssl_validation, default: false
    config_param :api_key, :string, default: ''
    config_param :logset, :string, default: 'main'

    # e.g. ['env:prod', 'app:myapp']
    # see https://github.com/DataDog/datadog-log-agent/blob/db13b53dfdd036d43acfb15089a43eb31548f09f/pkg/logagent/etc/conf.d/integration.yaml.example
    config_param :tags, :array, default: [], value_type: :string
    config_param :service, :string, default: '-'
    # e.g. 'nginx'
    config_param :source, :string, default: ''
    config_param :source_category, :string, default: ''

    config_section :buffer do
      config_set_default :@type, DEFAULT_BUFFER_TYPE
    end

    # e.g. 'http_access'
    # config_param :source_category, :string, default: ''

    # Specify project/instance metadata.
    #
    # project_id, zone, and vm_id are required to have valid values, which
    # can be obtained from the metadata service or set explicitly.
    # Otherwise, the plugin will fail to initialize.
    #
    # Note that while 'project id' properly refers to the alphanumeric name
    # of the project, the logging service will also accept the project number,
    # so either one is acceptable in this context.
    #
    # Whether to attempt to obtain metadata from the local metadata service.
    # It is safe to specify 'true' even on platforms with no metadata service.
    config_param :use_metadata_service, :bool, :default => true
    # These parameters override any values obtained from the metadata service.
    config_param :project_id, :string, :default => nil
    config_param :zone, :string, :default => nil
    config_param :vm_id, :string, :default => nil
    config_param :vm_name, :string, :default => nil

    # TODO: Correlate log messages to corresponding Datadog APM spans
    # config_param :trace_key, :string, :default => DEFAULT_TRACE_KEY

    # Whether to try to detect if the record is a text log entry with JSON
    # content that needs to be parsed.
    config_param :detect_json, :bool, :default => false

    # Whether to reject log entries with invalid tags. If this option is set to
    # false, tags will be made valid by converting any non-string tag to a
    # string, and sanitizing any non-utf8 or other invalid characters.
    config_param :require_valid_tags, :bool, :default => false

    # Whether to allow non-UTF-8 characters in user logs. If set to true, any
    # non-UTF-8 character would be replaced by the string specified by
    # 'non_utf8_replacement_string'. If set to false, any non-UTF-8 character
    # would trigger the plugin to error out.
    config_param :coerce_to_utf8, :bool, :default => true

    # If 'coerce_to_utf8' is set to true, any non-UTF-8 character would be
    # replaced by the string specified here.
    config_param :non_utf8_replacement_string, :string, :default => ' '

    # Whether to collect metrics about the plugin usage. The mechanism for
    # collecting and exposing metrics is controlled by the monitoring_type
    # parameter.
    config_param :enable_monitoring, :bool, :default => false
    config_param :monitoring_type, :string, :default => 'prometheus'

    # rubocop:enable Style/HashSyntax

    attr_reader :zone
    attr_reader :vm_id

    def initialize
      super
      # use the global logger
      @log = $log # rubocop:disable Style/GlobalVars
    end

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
    def build_payload(api_key_str:, msg:, extra_content:)
      "#{api_key_str} #{extra_content} #{msg}\\n"
    end

    def configure(conf)
      compat_parameters_convert(conf, :buffer, :inject)
      super

      if @api_key.size == 0
        @api_key = ENV['DD_LOG_API_KEY']
        if @api_key == '' || @api_key.nil?
          error_message = 'Unable to obtain api_key from DD_LOG_API_KEY'
          fail Fluent::ConfigError, error_message
        end
      end

      # If monitoring is enabled, register metrics in the default registry
      # and store metric objects for future use.
      if @enable_monitoring
        registry = Monitoring::MonitoringRegistryFactory.create @monitoring_type
        @successful_requests_count = registry.counter(
          :datadog_successful_requests_count,
          'A number of successful requests to the Datadog Log Intake API')
        @failed_requests_count = registry.counter(
          :datadog_failed_requests_count,
          'A number of failed requests to the Datadog Log Intake API,'\
            ' broken down by the error code')
        @ingested_entries_count = registry.counter(
          :datadog_ingested_entries_count,
          'A number of log entries ingested by Datadog Log Intake')
        @dropped_entries_count = registry.counter(
          :datadog_dropped_entries_count,
          'A number of log entries dropped by the Stackdriver output plugin')
        @retried_entries_count = registry.counter(
          :datadog_retried_entries_count,
          'The number of log entries that failed to be ingested by the'\
            ' Stackdriver output plugin due to a transient error and were'\
            ' retried')
      end

      @platform = detect_platform

      # Set required variables: @project_id, @vm_id, @vm_name and @zone.
      set_required_metadata_variables

      @default_tags = build_default_tags

      # The resource and labels are now set up; ensure they can't be modified
      # without first duping them.
      @default_tags.freeze

      # Log an informational message containing the Logs viewer URL
      @log.info 'Logs viewer address: https://example.com/logs/'
    end

    def start
      super
      init_api_client
      @successful_call = false
      @timenanos_warning = false
    end

    def shutdown
      super
      @conn.close unless @conn.nil?
    end

    def format(tag, time, record)
      record = inject_values_to_record(tag, time, record)
      [tag, time, record].to_msgpack
    end

    def formatted_to_msgpack_binary?
      true
    end

    def multi_workers_ready?
      true
    end

    def write(chunk)
      each_valid_record(chunk) do |_tag, time, record|
        if @detect_json
          # Save the timestamp and severity if available, then clear it out to
          # allow for determining whether we should parse the log or message
          # field.
          timestamp = record.delete('time')
          severity = record.delete('severity')

          # If the log is json, we want to export it as a structured log
          # unless there is additional metadata that would be lost.
          record_json = nil
          if record.length == 1
            %w(log message msg).each do |field|
              if record.key?(field)
                record_json = parse_json_or_nil(record[field])
              end
            end
          end
          record = record_json unless record_json.nil?
          # Restore timestamp and severity if necessary. Note that we don't
          # want to override these keys in the JSON we've just parsed.
          record['time'] ||= timestamp if timestamp
          record['severity'] ||= severity if severity
        end

        # TODO: Correlate Datadog APM spans with log messages
        # fq_trace_id = record.delete(@trace_key)
        # entry.trace = fq_trace_id if fq_trace_id

        begin
          msg = nil
          %w(log message msg).each do |field|
            msg = record[field] if record.key?(field)
          end

          tags = []

          kube = record['kubernetes'] || {}

          mappings = {
            'pod_name' => 'pod_name',
            'container_name' => 'container_name',
            'namespace_name' => 'kube_namespace'
          }

          mappings.each do |json_key, tag_key|
            tags << "#{tag_key}=#{kube[json_key]}" if kube.key? json_key
          end

          if kube.key? 'labels'
            labels = kube['labels']
            labels.each do |k, v|
              tags << "kube_#{k}=#{v}"
            end
          end

          # TODO: Include K8S tags like
          # - kube_daemon_set=$daemonset_name
          # - kube_deployment=$deployment_name
          # - kube_replica_set=$replicaset_name
          # -

          tags.concat(@default_tags)

          datetime = Time.at(Fluent::EventTime.new(time).to_r).utc.to_datetime
          timestamp_str = datetime.rfc3339(6)

          payload = build_payload(
            api_key_str: build_api_key_str(api_key: @api_key, logset: @logset),
            msg: truncate_message(msg),
            extra_content: build_extra_content(
              timestamp: timestamp_str,
              hostname: @vm_id,
              service: @service,
              tags_payload: build_tags_payload(
                config_tags: tags,
                source: @source,
                source_category: @source_category
              )
            )
          )

          entries_count = 1
          @conn.write(payload)
          @log.debug 'Sent payload to Datadog.', payload: payload
          increment_successful_requests_count
          increment_ingested_entries_count(entries_count)

          # Let the user explicitly know when the first call succeeded, to aid
          # with verification and troubleshooting.
          unless @successful_call
            @successful_call = true
            @log.info 'Successfully sent to Datadog.'
          end

        rescue => error
          increment_failed_requests_count
          increment_retried_entries_count(entries_count)
          # RPC cancelled, so retry via re-raising the error.
          @log.debug "Retrying #{entries_count} log message(s) later.",
                     error: error.to_s
          raise error
        end
      end
    end

    private

    def parse_json_or_nil(input)
      # Only here to please rubocop...
      return nil if input.nil?

      input.each_codepoint do |c|
        if c == 123
          # left curly bracket (U+007B)
          begin
            return JSON.parse(input)
          rescue JSON::ParserError
            return nil
          end
        else
          # Break (and return nil) unless the current character is whitespace,
          # in which case we continue to look for a left curly bracket.
          # Whitespace as per the JSON spec are: tabulation (U+0009),
          # line feed (U+000A), carriage return (U+000D), and space (U+0020).
          break unless c == 9 || c == 10 || c == 13 || c == 32
        end # case
      end # do
      nil
    end

    # "enum" of Platform values
    module Platform
      OTHER = 0  # Other/unkown platform
      GCE = 1    # Google Compute Engine
      EC2 = 2    # Amazon EC2
    end

    # Determine what platform we are running on by consulting the metadata
    # service (unless the user has explicitly disabled using that).
    def detect_platform
      unless @use_metadata_service
        @log.info 'use_metadata_service is false; not detecting platform'
        return Platform::OTHER
      end

      begin
        open('http://' + METADATA_SERVICE_ADDR) do |f|
          if f.meta['metadata-flavor'] == 'Google'
            @log.info 'Detected GCE platform'
            return Platform::GCE
          end
          if f.meta['server'] == 'EC2ws'
            @log.info 'Detected EC2 platform'
            return Platform::EC2
          end
        end
      rescue StandardError => e
        @log.error 'Failed to access metadata service: ', error: e
      end

      @log.info 'Unable to determine platform'
      Platform::OTHER
    end

    def fetch_gce_metadata(metadata_path)
      fail "Called fetch_gce_metadata with platform=#{@platform}" unless
        @platform == Platform::GCE
      # See https://cloud.google.com/compute/docs/metadata
      open('http://' + METADATA_SERVICE_ADDR + '/computeMetadata/v1/' +
           metadata_path, 'Metadata-Flavor' => 'Google', &:read)
    end

    # EC2 Metadata server returns everything in one call. Store it after the
    # first fetch to avoid making multiple calls.
    def ec2_metadata
      fail "Called ec2_metadata with platform=#{@platform}" unless
        @platform == Platform::EC2
      unless @ec2_metadata
        # See http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html
        open('http://' + METADATA_SERVICE_ADDR +
             '/latest/dynamic/instance-identity/document') do |f|
          contents = f.read
          @ec2_metadata = JSON.parse(contents)
        end
      end

      @ec2_metadata
    end

    # Set required variables like @vm_id, @vm_name and @zone.
    def set_required_metadata_variables
      set_vm_id
      set_vm_name
      set_zone

      # All metadata parameters must now be set.
      missing = []
      missing << 'zone' unless @zone
      missing << 'vm_id' unless @vm_id
      missing << 'vm_name' unless @vm_name
      return if missing.empty?
      fail Fluent::ConfigError, 'Unable to obtain metadata parameters: ' +
        missing.join(' ')
    end

    # 1. Return the value if it is explicitly set in the config already.
    # 2. If not, try to retrieve it by calling metadata servers directly.
    def set_vm_id
      @vm_id ||= ec2_metadata['instanceId'] if @platform == Platform::EC2
    rescue StandardError => e
      @log.error 'Failed to obtain vm_id: ', error: e
    end

    # 1. Return the value if it is explicitly set in the config already.
    # 2. If not, try to retrieve it locally.
    def set_vm_name
      @vm_name ||= Socket.gethostname
    rescue StandardError => e
      @log.error 'Failed to obtain vm name: ', error: e
    end

    # 1. Return the value if it is explicitly set in the config already.
    # 2. If not, try to retrieve it locally.
    def set_zone
      @zone ||= 'aws:' + ec2_metadata['availabilityZone'] if
        @platform == Platform::EC2 && ec2_metadata.key?('availabilityZone')
    rescue StandardError => e
      @log.error 'Failed to obtain location: ', error: e
    end

    # Determine agent level monitored resource labels based on the resource
    # type. Each resource type has its own labels that need to be filled in.
    def build_default_tags
      aws_account_id = ec2_metadata['accountId'] if
          ec2_metadata.key?('accountId')
      # #host:i-09fbfed2672d2c6bf
      %W(host=#{@vm_id} zone=#{@zone} aws_account_id=#{aws_account_id})
        .concat @tags
    end

    # Filter out invalid non-Hash entries.
    def each_valid_record(chunk)
      chunk.msgpack_each do |event|
        record = event.last
        unless record.is_a?(Hash)
          @log.warn 'Dropping log entries with malformed record: ' \
                    "'#{record.inspect}'. " \
                    'A log record should be in JSON format.'
          next
        end
        tag = record.first
        sanitized_tag = sanitize_tag(tag)
        if sanitized_tag.nil?
          @log.warn "Dropping log entries with invalid tag: '#{tag.inspect}'." \
                    ' A tag should be a string with utf8 characters.'
          next
        end
        yield event
      end
    end

    # Given a tag, returns the corresponding valid tag if possible, or nil if
    # the tag should be rejected. If 'require_valid_tags' is false, non-string
    # tags are converted to strings, and invalid characters are sanitized;
    # otherwise such tags are rejected.
    def sanitize_tag(tag)
      if @require_valid_tags &&
         (!tag.is_a?(String) || tag == '' || convert_to_utf8(tag) != tag)
        return nil
      end
      tag = convert_to_utf8(tag.to_s)
      tag = '_' if tag == ''
      tag
    end

    def init_api_client
      ssl = true
      ssl = { verify_mode: OpenSSL::SSL::VERIFY_NONE } if @skip_ssl_validation
      server = "#{@log_dd_url}:#{@log_dd_port}"
      @conn = Net::TCPClient.new(server: server, ssl: ssl)
    end

    # Encode as UTF-8. If 'coerce_to_utf8' is set to true in the config, any
    # non-UTF-8 character would be replaced by the string specified by
    # 'non_utf8_replacement_string'. If 'coerce_to_utf8' is set to false, any
    # non-UTF-8 character would trigger the plugin to error out.
    def convert_to_utf8(input)
      if @coerce_to_utf8
        input.encode(
          'utf-8',
          invalid: :replace,
          undef: :replace,
          replace: @non_utf8_replacement_string)
      else
        begin
          input.encode('utf-8')
        rescue EncodingError
          @log.error 'Encountered encoding issues potentially due to non ' \
                     'UTF-8 characters. To allow non-UTF-8 characters and ' \
                     'replace them with spaces, please set "coerce_to_utf8" ' \
                     'to true.'
          raise
        end
      end
    end

    def ensure_array(value)
      Array.try_convert(value) || (fail JSON::ParserError, "#{value.class}")
    end

    def ensure_hash(value)
      Hash.try_convert(value) || (fail JSON::ParserError, "#{value.class}")
    end

    # Increment the metric for the number of successful requests.
    def increment_successful_requests_count
      return unless @successful_requests_count
      @successful_requests_count.increment
    end

    # Increment the metric for the number of failed requests, labeled by
    # the provided status code.
    def increment_failed_requests_count
      return unless @failed_requests_count
      @failed_requests_count.increment
    end

    # Increment the metric for the number of log entries, successfully
    # ingested by the Datadog Log Intake API.
    def increment_ingested_entries_count(count)
      return unless @ingested_entries_count
      @ingested_entries_count.increment({}, count)
    end

    # Increment the metric for the number of log entries that were dropped
    # and not ingested by the Datadog Log Intake API.
    def increment_dropped_entries_count(count)
      return unless @dropped_entries_count
      @dropped_entries_count.increment({}, count)
    end

    # Increment the metric for the number of log entries that were dropped
    # and not ingested by the Datadog Log Intake API.
    def increment_retried_entries_count(count)
      return unless @retried_entries_count
      @retried_entries_count.increment({}, count)
    end
  end
end
