Gem::Specification.new do |gem|
  gem.name          = 'fluent-plugin-datadog-log'
  gem.description   = <<-eos
   Fluentd output plugin for the Datadog Log Intake API, which will make
   logs viewable in the Datadog's log viewer.
eos
  gem.summary       = 'fluentd output plugin for the Datadog Log Intake API'
  gem.homepage      = \
    'https://github.com/mumoshu/fluent-plugin-datadog-log'
  gem.license       = 'Apache-2.0'
  gem.version       = '0.1.0.rc8'
  gem.authors       = ['Yusuke KUOKA']
  gem.email         = ['ykuoka@gmail.com']
  gem.required_ruby_version = Gem::Requirement.new('>= 2.0')

  gem.files         = Dir['**/*'].keep_if { |file| File.file?(file) }
  gem.test_files    = gem.files.grep(/^(test)/)
  gem.require_paths = ['lib']

  gem.add_runtime_dependency 'fluentd', '~> 0.14'
  # gem.add_runtime_dependency 'datadog-log-api-client', '~> 0.1'
  gem.add_runtime_dependency 'json', '~> 1.8'

  gem.add_dependency 'net_tcp_client', '~> 2.0.1'
  gem.add_dependency 'prometheus-client', '~> 0.7.1'

  gem.add_development_dependency 'mocha', '~> 1.1'
  gem.add_development_dependency 'rake', '~> 10.3'
  gem.add_development_dependency 'rubocop', '~> 0.35.0'
  gem.add_development_dependency 'webmock', '~> 2.3.1'
  gem.add_development_dependency 'test-unit', '~> 3.0'
end
