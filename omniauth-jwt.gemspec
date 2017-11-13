# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'omniauth/jwt/version'

Gem::Specification.new do |spec|
  spec.name          = "aca-omniauth-jwt-blocking"
  spec.version       = Omniauth::JWT::VERSION
  spec.authors       = ["Michael Bleigh", "Tobias Haar"]
  spec.email         = ["mbleigh@mbleigh.com", "tobias.haar@sage.com"]
  spec.description   = %q{An OmniAuth strategy to accept JWT-based single sign-on.}
  spec.summary       = %q{An OmniAuth strategy to accept JWT-based single sign-on.}
  spec.homepage      = "http://github.com/Sage/omniauth-jwt"
  spec.license       = "MIT"

  spec.files         = `git ls-files`.split($/)
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = ["lib"]

  spec.add_development_dependency "bundler", "~> 1.3"
  spec.add_development_dependency "rake"
  spec.add_development_dependency "rspec"
  spec.add_development_dependency "guard"
  spec.add_development_dependency "guard-rspec"
  spec.add_development_dependency "rack-test"

  spec.add_dependency "jwt", "~> 1.0"
  spec.add_dependency "omniauth", "~> 1.1"
end
