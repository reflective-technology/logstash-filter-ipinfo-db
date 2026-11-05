Gem::Specification.new do |s|
  s.name          = 'logstash-filter-ipinfo-db-zuin'
  s.version       = '0.3.0'
  s.licenses      = ['Apache-2.0']
  s.summary       = 'Logstash Filter Plugin for IPinfoDb'
  s.description   = 'This gem is a Logstash plugin required to be installed on top of the Logstash core pipeline ' \
                    'using $LS_HOME/bin/logstash-plugin install gemname. This gem is not a stand-alone program. ' \
                    'It looks up the country and ASN of IP addresses in the ipinfo.io free country and ASN database.'
  s.homepage      = 'https://github.com/reflective-technology/logstash-filter-ipinfo-db'
  s.authors       = ['ZUIN RD']
  s.email         = 'rd@zuin.ai'
  s.require_paths = ['lib']
  # Oldest runtime verified in CI: Logstash 8.19 ships JRuby 9.4, which is Ruby 3.1 compatible.
  s.required_ruby_version = '>= 3.1'

  # Files
  s.files = Dir['lib/**/*','spec/**/*','docs/**/*','*.gemspec','*.md','CONTRIBUTORS','Gemfile','LICENSE']
   # Tests
  s.test_files = s.files.grep(%r{^(test|spec|features)/})

  # Special flag to let us know this is actually a logstash plugin
  s.metadata = { "logstash_plugin" => "true", "logstash_group" => "filter" }

  # Gem dependencies
  s.add_runtime_dependency "logstash-core-plugin-api", "~> 2.0"
  # logstash-core itself depends on down ~> 5.2.0, so this must allow 5.2.x.
  s.add_runtime_dependency "down", "~> 5.2"
  s.add_runtime_dependency "maxmind-db", "~> 1.2"
  s.add_development_dependency 'logstash-devutils', '~> 2.6'
end
