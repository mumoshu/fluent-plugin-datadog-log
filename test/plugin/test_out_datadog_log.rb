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

require_relative 'base_test'

# Unit tests for Datadog Log plugin
class DatadogLogOutputTest < Test::Unit::TestCase
  include BaseTest

  def test_configure
    new_stub_context do
      setup_ec2_metadata_stubs

      d = create_driver(<<-EOC)
        type datadog_log
        api_key myapikey
        service myservice
        source mysource
      EOC

      assert_equal 'myapikey', d.instance.api_key
      assert_equal 'myservice', d.instance.service
      assert_equal 'mysource', d.instance.source
    end
  end

  def test_configure_with_env
    new_stub_context do
      setup_ec2_metadata_stubs

      ENV.stubs(:[])
        .with('DD_API_KEY')
        .returns('myapikey_from_env')

      ENV.stubs(:[])
        .with(Not equals 'DD_API_KEY')
        .returns('')
        .times(3)

      d = create_driver(<<-EOC)
        type datadog_log
        service myservice
        source mysource
      EOC

      assert_equal 'myapikey_from_env', d.instance.api_key
      assert_equal 'myservice', d.instance.service
      assert_equal 'mysource', d.instance.source
    end
  end

  def test_write
    new_stub_context do
      setup_ec2_metadata_stubs

      timestamp_str = '2006-01-02T15:04:05.000000+00:00'
      t = DateTime.rfc3339(timestamp_str).to_time
      time = Fluent::EventTime.from_time(t)
      d = create_driver(<<-EOC)
        type datadog_log
        api_key myapikey
        service myservice
        source mysource
        source_category mysourcecategory
        logset mylogset
        log_level debug
      EOC
      conn = StubConn.new
      fluentd_tag = 'mytag'
      Net::TCPClient.stubs(:new)
        .with(server: 'intake.logs.datadoghq.com:10516', ssl: true)
        .returns(conn)
      d.run(default_tag: fluentd_tag) do
        record = {
          'log' => 'mymsg'
        }
        d.feed(time, record)
      end

      # fail d.logs.inspect
      assert_equal(1, d.logs.count { |l| l =~ /Sent payload to Datadog/ })
      assert_equal(1, conn.sent.size)
      # rubocop:disable LineLength
      payload = %(myapikey/mylogset <46>0 2006-01-02T15:04:05.000000+00:00 i-81c16767 myservice - - [dd ddsource="mysource"][dd ddsourcecategory="mysourcecategory"][dd ddtags="host=i-81c16767,zone=aws:us-west-2b,aws_account_id=123456789012"] mymsg\n)
      # rubocop:enable LineLength
      assert_equal(payload, conn.sent.first)
    end
  end

  def test_write_kube
    new_stub_context do
      setup_ec2_metadata_stubs

      timestamp_str = '2006-01-02T15:04:05.000000+00:00'
      t = DateTime.rfc3339(timestamp_str).to_time
      time = Fluent::EventTime.from_time(t)
      d = create_driver(<<-EOC)
        type datadog_log
        api_key myapikey
        service myservice
        source mysource
        source_category mysourcecategory
        logset mylogset
        log_level debug
        tags ["kube_cluster=MyCluster", "mykey=myval"]
      EOC
      conn = StubConn.new
      fluentd_tag = 'mytag'
      Net::TCPClient.stubs(:new)
        .with(server: 'intake.logs.datadoghq.com:10516', ssl: true)
        .returns(conn)
      d.run(default_tag: fluentd_tag) do
        record = {
          'log' => 'mymsg',
          'docker' => {
            'container_id' => 'myfullcontainerid'
          },
          'kubernetes' => {
            'namespace' => 'myns',
            'pod_name' => 'mypod',
            'container_name' => 'mycontainer',
            'labels' => {
              'k8s-app' => 'myapp'
            },
            'annotations' => {
              # rubocop:disable LineLength
              # kubernetes.io is translated to kubernetes_io by kubernetes metadata filter
              'kubernetes_io/created-by' => '{"kind":"SerializedReference","apiVersion":"v1","reference":{"kind":"Deployment","namespace":"default","name":"myapp","uid":"d67e8857-c2dc-11e7-aed9-066d23381f8c","apiVersion":"extensions","resourceVersion":"289"}}'
              # rubocop:enable LineLength
            }
          }
        }
        d.feed(time, record)
      end

      # fail d.logs.inspect
      assert_equal(1, d.logs.count { |l| l =~ /Sent payload to Datadog/ })
      assert_equal(1, conn.sent.size)
      # rubocop:disable LineLength
      payload = %(myapikey/mylogset <46>0 2006-01-02T15:04:05.000000+00:00 i-81c16767 myapp - - [dd ddsource="mypod"][dd ddsourcecategory="mycontainer"][dd ddtags="pod_name=mypod,container_name=mycontainer,kube_k8s-app=myapp,kube_deployment=myapp,host=i-81c16767,zone=aws:us-west-2b,aws_account_id=123456789012,kube_cluster=MyCluster,mykey=myval"] mymsg\n)
      # rubocop:enable LineLength
      assert_equal(payload, conn.sent.first)
    end
  end

  def test_prometheus_metrics
    new_stub_context do
      setup_ec2_metadata_stubs
      timestamp_str = '2006-01-02T15:04:05.000000+00:00'
      t = DateTime.rfc3339(timestamp_str).to_time
      time = Fluent::EventTime.from_time(t)
      [
        # Single successful request.
        [false, 0, 1, 1, [1, 0, 1, 0, 0]],
        # Several successful requests.
        [false, 0, 2, 1, [2, 0, 2, 0, 0]]
      ].each do |_should_fail, _code, request_count, entry_count, metric_values|
        setup_prometheus
        (1..request_count).each do
          d = create_driver(<<-EOC)
            type datadog_log
            api_key myapikey
            service myservice
            source mysource
            source_category mysourcecategory
            logset mylogset
            log_level debug
            enable_monitoring true
          EOC
          conn = StubConn.new
          Net::TCPClient.stubs(:new)
            .with(server: 'intake.logs.datadoghq.com:10516', ssl: true)
            .returns(conn)
          d.run(default_tag: 'mytag') do
            (1..entry_count).each do |i|
              d.feed time, 'message' => log_entry(i.to_s)
            end
          end
        end
        successful_requests_count, failed_requests_count,
          ingested_entries_count, dropped_entries_count,
          retried_entries_count = metric_values
        assert_prometheus_metric_value(:datadog_successful_requests_count,
                                       successful_requests_count)
        assert_prometheus_metric_value(:datadog_failed_requests_count,
                                       failed_requests_count)
        assert_prometheus_metric_value(:datadog_ingested_entries_count,
                                       ingested_entries_count)
        assert_prometheus_metric_value(:datadog_dropped_entries_count,
                                       dropped_entries_count)
        assert_prometheus_metric_value(:datadog_retried_entries_count,
                                       retried_entries_count)
      end
    end
  end

  def test_struct_payload_non_utf8_log
    # d.emit('msg' => log_entry(0),
    #        'normal_key' => "test#{non_utf8_character}non utf8",
    #        "non_utf8#{non_utf8_character}key" => 5000,
    #        'nested_struct' => { "non_utf8#{non_utf8_character}key" => \
    #                             "test#{non_utf8_character}non utf8" },
    #        'null_field' => nil)
  end

  class StubConn
    attr_reader :sent

    def initialize
      @sent = []
    end

    def retry_on_connection_failure
      yield
    end

    def write(payload)
      @sent << payload
    end

    def close
    end
  end

  private

  # Use the right single quotation mark as the sample non-utf8 character.
  def non_utf8_character
    [0x92].pack('C*')
  end

  # For an optional field with default values, Protobuf omits the field when it
  # is deserialized to json. So we need to add an extra check for gRPC which
  # uses Protobuf.
  #
  # An optional block can be passed in if we need to assert something other than
  # a plain equal. e.g. assert_in_delta.
  def assert_equal_with_default(field, expected_value, default_value, entry)
    if expected_value == default_value
      assert_nil field
    elsif block_given?
      yield
    else
      assert_equal expected_value, field, entry
    end
  end

  # Get the fields of the payload.
  def get_fields(payload)
    payload['fields']
  end

  # Get the value of a struct field.
  def get_struct(field)
    field['structValue']
  end

  # Get the value of a string field.
  def get_string(field)
    field['stringValue']
  end

  # Get the value of a number field.
  def get_number(field)
    field['numberValue']
  end

  # The null value.
  def null_value
    { 'nullValue' => 'NULL_VALUE' }
  end
end
