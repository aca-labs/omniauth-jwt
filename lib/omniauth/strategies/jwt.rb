require 'omniauth'
require 'jwt'
require 'json'
require 'uv-rays'

module OmniAuth
  module Strategies
    VivantApi = UV::HttpEndpoint.new('https://api.internationaltowers.com', tls_options: {host_name: 'api.internationaltowers.com'})

    class JWT
      class ClaimInvalid < StandardError; end

      include OmniAuth::Strategy

      args [:app_token, :secret]

      option :title, 'Vivant Authentication'
      option :app_token, nil
      option :secret, nil
      option :algorithm, 'HS256'
      option :uid_claim, 'id'
      option :required_claims, %w(firstName lastName email)
      option :info_map, {"name" => proc { |raw| "#{raw['firstName']} #{raw['lastName']}" }, "email" => "email"}
      option :auth_url, nil
      option :valid_within, nil


      def request_phase
        f = OmniAuth::Form.new(:title => (options[:title] || "LDAP Authentication"), :url => callback_path)
        f.text_field 'Login', 'username'
        f.password_field 'Password', 'password'
        f.button "Sign In"
        f.to_response
      end

      attr_reader :decoded

      def callback_phase
        return fail!(:missing_credentials) if missing_credentials?

        req = JSON.generate({
          username: params['username'],
          password: params['password'],
          appToken: options.app_token
        })

        response = VivantApi.post(path: options.auth_url, body: req, headers: {
          'content-type' => 'application/json',
          'Authorization' => "Bearer #{options.app_token}"
        }).value

        if response.status == 200
          @decoded, _ = ::JWT.decode(JSON.parse(response.body)['userToken'], secret, options.algorithm)
          @decoded = @decoded['userInfo']

          (options.required_claims || []).each do |field|
            raise ClaimInvalid.new("Missing required '#{field}' claim.") if !@decoded.key?(field.to_s)
          end
          raise ClaimInvalid.new("Missing required 'iat' claim.") if options.valid_within && !@decoded["iat"]
          raise ClaimInvalid.new("'iat' timestamp claim is too skewed from present.") if options.valid_within && (Time.now.to_i - @decoded["iat"]).abs > options.valid_within

          super
        else
          fail! :invalid_credentials
        end
      rescue ClaimInvalid => e
        fail! :claim_invalid, e
      end

      uid do
        if options.uid_claim.is_a?(String)
          decoded[options.uid_claim]
        else
          uid_lookup.uid(decoded)
        end
      end

      extra do
        {:raw_info => decoded}
      end

      info do
        options.info_map.inject({}) do |h,(k,v)|
          h[k.to_s] = v.respond_to?(:call) ? v.call(decoded) : decoded[v.to_s]
          h
        end
      end

      private

      def secret
        if options.secret.is_a?(String)
          options.secret
        else
          secret_lookup.secret
        end
      end

      def secret_lookup
        @secret_lookup ||= options.secret.new(request)
      end

      def uid_lookup
        @uid_lookup ||= options.uid_claim.new(request)
      end

      def params
        request.params
      end

      def missing_credentials?
        params['username'].nil? or params['username'].empty? or params['password'].nil? or params['password'].empty?
      end
    end

    class Jwt < JWT; end
  end
end
