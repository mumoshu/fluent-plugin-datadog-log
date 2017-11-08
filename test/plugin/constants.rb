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

# Constants used by unit tests for Datadog plugin.
module Constants
  # Generic attributes.
  HOSTNAME = Socket.gethostname

  # TODO(qingling128) Separate constants into different submodules.
  # Attributes used for the GCE metadata service.
  ZONE = 'us-central1-b'
  VM_ID = '9876543210'

  # Attributes used for the Metadata Agent resources.
  METADATA_ZONE = 'us-central1-c'
  METADATA_VM_ID = '0123456789'

  # Attributes used for custom (overridden) configs.
  CUSTOM_PROJECT_ID = 'test-custom-project-id'
  CUSTOM_ZONE = 'us-custom-central1-b'
  CUSTOM_VM_ID = 'C9876543210'
  CUSTOM_HOSTNAME = 'custom.hostname.org'

  # Attributes used for the EC2 metadata service.
  EC2_PROJECT_ID = 'test-ec2-project-id'
  EC2_ZONE = 'us-west-2b'
  EC2_PREFIXED_ZONE = 'aws:' + EC2_ZONE
  EC2_VM_ID = 'i-81c16767'
  EC2_ACCOUNT_ID = '123456789012'

  # The formatting here matches the format used on the VM.
  EC2_IDENTITY_DOCUMENT = %({
    "accountId" : "#{EC2_ACCOUNT_ID}",
    "availabilityZone" : "#{EC2_ZONE}",
    "instanceId" : "#{EC2_VM_ID}"
  })

  # Managed VMs specific labels.
  MANAGED_VM_BACKEND_NAME = 'default'
  MANAGED_VM_BACKEND_VERSION = 'guestbook2.0'

  # Docker Container labels.
  DOCKER_CONTAINER_ID = '0d0f03ff8d3c42688692536d1af77a28cd135c0a5c531f25a31'
  DOCKER_CONTAINER_NAME = 'happy_hippo'
  DOCKER_CONTAINER_STREAM_STDOUT = 'stdout'
  DOCKER_CONTAINER_STREAM_STDERR = 'stderr'
  # Timestamp for 1234567890 seconds and 987654321 nanoseconds since epoch.
  DOCKER_CONTAINER_TIMESTAMP = '2009-02-13T23:31:30.987654321Z'
  DOCKER_CONTAINER_SECONDS_EPOCH = 1_234_567_890
  DOCKER_CONTAINER_NANOS = 987_654_321

  # Container Engine / Kubernetes specific labels.
  CONTAINER_CLUSTER_NAME = 'cluster-1'
  CONTAINER_NAMESPACE_ID = '898268c8-4a36-11e5-9d81-42010af0194c'
  CONTAINER_NAMESPACE_NAME = 'kube-system'
  CONTAINER_POD_ID = 'cad3c3c4-4b9c-11e5-9d81-42010af0194c'
  CONTAINER_POD_NAME = 'redis-master-c0l82.foo.bar'
  CONTAINER_CONTAINER_NAME = 'redis'
  CONTAINER_LABEL_KEY = 'component'
  CONTAINER_LABEL_VALUE = 'redis-component'
  CONTAINER_STREAM = 'stdout'
  CONTAINER_SEVERITY = 'INFO'
  # Timestamp for 1234567890 seconds and 987654321 nanoseconds since epoch.
  CONTAINER_TIMESTAMP = '2009-02-13T23:31:30.987654321Z'
  CONTAINER_SECONDS_EPOCH = 1_234_567_890
  CONTAINER_NANOS = 987_654_321

  # Cloud Functions specific labels.
  CLOUDFUNCTIONS_FUNCTION_NAME = '$My_Function.Name-@1'
  CLOUDFUNCTIONS_REGION = 'us-central1'
  CLOUDFUNCTIONS_EXECUTION_ID = '123-0'
  CLOUDFUNCTIONS_CLUSTER_NAME = 'cluster-1'
  CLOUDFUNCTIONS_NAMESPACE_NAME = 'default'
  CLOUDFUNCTIONS_POD_NAME = 'd.dc.myu.uc.functionp.pc.name-a.a1.987-c0l82'
  CLOUDFUNCTIONS_CONTAINER_NAME = 'worker'

  # Dataflow specific labels.
  DATAFLOW_REGION = 'us-central1'
  DATAFLOW_JOB_NAME = 'job_name_1'
  DATAFLOW_JOB_ID = 'job_id_1'
  DATAFLOW_STEP_ID = 'step_1'
  DATAFLOW_TAG = 'dataflow-worker'

  # Dataproc specific labels.
  DATAPROC_CLUSTER_NAME = 'test-cluster'
  DATAPROC_CLUSTER_UUID = '00000000-0000-0000-0000-000000000000'
  DATAPROC_REGION = 'unittest'

  # ML specific labels.
  ML_REGION = 'us-central1'
  ML_JOB_ID = 'job_name_1'
  ML_TASK_NAME = 'task_name_1'
  ML_TRIAL_ID = 'trial_id_1'
  ML_LOG_AREA = 'log_area_1'
  ML_TAG = 'master-replica-0'

  # Parameters used for authentication.
  AUTH_GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:jwt-bearer'
  FAKE_AUTH_TOKEN = 'abc123'

  # Information about test credentials files.
  # path: Path to the credentials file.
  # project_id: ID of the project, which must correspond to the file contents.
  IAM_CREDENTIALS = {
    path: 'test/plugin/data/iam-credentials.json',
    project_id: 'fluent-test-project'
  }
  LEGACY_CREDENTIALS = {
    path: 'test/plugin/data/credentials.json',
    project_id: '847859579879'
  }
  INVALID_CREDENTIALS = {
    path: 'test/plugin/data/invalid_credentials.json',
    project_id: ''
  }

  # Configuration files for various test scenarios.
  APPLICATION_DEFAULT_CONFIG = %(

  )

  DETECT_JSON_CONFIG = %(
    detect_json true
  )

  PARTIAL_SUCCESS_CONFIG = %(
    partial_success true
  )

  REQUIRE_VALID_TAGS_CONFIG = %(
    require_valid_tags true
  )

  NO_METADATA_SERVICE_CONFIG = %(
    use_metadata_service false
  )

  PROMETHEUS_ENABLE_CONFIG = %(
    enable_monitoring true
    monitoring_type prometheus
  )

  CUSTOM_METADATA_CONFIG = %(
    zone #{CUSTOM_ZONE}
    vm_id #{CUSTOM_VM_ID}
    vm_name #{CUSTOM_HOSTNAME}
  )

  # Service configurations for various services.

  CUSTOM_LABELS_MESSAGE = {
    'customKey' => 'value'
  }
  # Tags and their sanitized and encoded version.
  VALID_TAGS = {
    'test' => 'test',
    'germanß' => 'german%C3%9F',
    'chinese中' => 'chinese%E4%B8%AD',
    'specialCharacter/_-.' => 'specialCharacter%2F_-.',
    'abc@&^$*' => 'abc%40%26%5E%24%2A',
    '@&^$*' => '%40%26%5E%24%2A'
  }
  INVALID_TAGS = {
    # Non-string tags.
    123 => '123',
    1.23 => '1.23',
    [1, 2, 3] => '%5B1%2C%202%2C%203%5D',
    { key: 'value' } => '%7B%22key%22%3D%3E%22value%22%7D',
    # Non-utf8 string tags.
    "nonutf8#{[0x92].pack('C*')}" => 'nonutf8%20',
    "abc#{[0x92].pack('C*')}" => 'abc%20',
    "#{[0x92].pack('C*')}" => '%20',
    # Empty string tag.
    '' => '_'
  }
  ALL_TAGS = VALID_TAGS.merge(INVALID_TAGS)
end
