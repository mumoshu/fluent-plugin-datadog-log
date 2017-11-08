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

require 'helper'
require 'mocha/test_unit'
require 'webmock/test_unit'
require 'prometheus/client'
require 'fluent/test/driver/output'
require 'fluent/test/helpers'

require_relative 'constants'

# Unit tests for Datadog plugin
module BaseTest
  include Constants
  include Fluent::Test::Helpers

  def setup
    Fluent::Test.setup
    require 'fluent/plugin/out_datadog'
    @logs_sent = []
  end

  def create_driver(conf = APPLICATION_DEFAULT_CONFIG)
    Fluent::Test::Driver::Output.new(Fluent::Plugin::DatadogOutput)
      .configure(conf)
  end

  private

  def setup_no_metadata_service_stubs
    # Simulate a machine with no metadata service present
    stub_request(:any, %r{http://169.254.169.254/.*})
      .to_raise(Errno::EHOSTUNREACH)
  end

  def setup_ec2_metadata_stubs
    # Stub the root, used for platform detection.
    stub_request(:get, 'http://169.254.169.254')
      .to_return(status: 200, headers: { 'Server' => 'EC2ws' })

    # Stub the identity document lookup made by the agent.
    stub_request(:get, 'http://169.254.169.254/latest/dynamic/' \
                 'instance-identity/document')
      .to_return(body: EC2_IDENTITY_DOCUMENT, status: 200,
                 headers: { 'Content-Length' => EC2_IDENTITY_DOCUMENT.length })
  end

  def setup_logging_stubs
    yield
  end

  def setup_prometheus
    Prometheus::Client.registry.instance_variable_set('@metrics', {})
  end

  # Provide a stub context that initializes @logs_sent, executes the block and
  # resets WebMock at the end.
  def new_stub_context
    @logs_sent = []
    yield
    WebMock.reset!
  end

  # Container.

  def container_tag_with_container_name(container_name)
    "kubernetes.#{CONTAINER_POD_NAME}_#{CONTAINER_NAMESPACE_NAME}_" \
      "#{container_name}"
  end

  def container_log_entry_with_metadata(
      log, container_name = CONTAINER_CONTAINER_NAME)
    {
      log: log,
      stream: CONTAINER_STREAM,
      time: CONTAINER_TIMESTAMP,
      kubernetes: {
        namespace_id: CONTAINER_NAMESPACE_ID,
        namespace_name: CONTAINER_NAMESPACE_NAME,
        pod_id: CONTAINER_POD_ID,
        pod_name: CONTAINER_POD_NAME,
        container_name: container_name,
        labels: {
          CONTAINER_LABEL_KEY => CONTAINER_LABEL_VALUE
        }
      }
    }
  end

  def container_log_entry(log, stream = CONTAINER_STREAM)
    {
      log: log,
      stream: stream,
      time: CONTAINER_TIMESTAMP
    }
  end

  # Docker Container.

  def docker_container_stdout_stderr_log_entry(
    log, stream = DOCKER_CONTAINER_STREAM_STDOUT)
    severity = if stream == DOCKER_CONTAINER_STREAM_STDOUT
                 'INFO'
               else
                 'ERROR'
               end
    {
      log: log,
      source: stream,
      severity: severity
    }
  end

  def docker_container_application_log_entry(log)
    {
      log: log,
      time: DOCKER_CONTAINER_TIMESTAMP
    }
  end

  def log_entry(i)
    "test log entry #{i}"
  end

  # This module expects the methods below to be overridden.

  def assert_prometheus_metric_value(metric_name, expected_value, labels = {})
    metric = Prometheus::Client.registry.get(metric_name)
    assert_not_nil(metric)
    assert_equal(expected_value, metric.get(labels))
  end

  # Get the fields of the payload.
  def get_fields(_payload)
    _undefined
  end

  # Get the value of a struct field.
  def get_struct(_field)
    _undefined
  end

  # Get the value of a string field.
  def get_string(_field)
    _undefined
  end

  # Get the value of a number field.
  def get_number(_field)
    _undefined
  end

  # The null value.
  def null_value(_field)
    _undefined
  end

  def _undefined
    fail "Method #{__callee__} is unimplemented and needs to be overridden."
  end
end
