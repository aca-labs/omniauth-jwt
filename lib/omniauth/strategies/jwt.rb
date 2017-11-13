require 'omniauth'
require 'jwt'
require 'json'
require 'net/http'

module OmniAuth
  module Strategies
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

        if params['token'] && !params['token'].empty?
          parse_token(params['token'])
          super
        else
          req = {
            username: params['username'],
            password: params['password'],
            appToken: options.app_token
          }.to_json

          http = Net::HTTP.new('api.internationaltowers.com', 443)
          http.use_ssl = true

          request = Net::HTTP::Post.new(options.auth_url)
          request.body = req
          request.content_type = 'application/json'
          request['Authorization'] = "Bearer #{options.app_token}"

          response = http.request(request)

          if response.code == '200'
            parse_token(JSON.parse(response.body)['userToken'])
            super
          else
            fail! :invalid_credentials
          end
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
      
      def parse_token(data)
        @decoded, _ = ::JWT.decode(data, secret, options.algorithm)
        @decoded = @decoded['userInfo']

        (options.required_claims || []).each do |field|
          raise ClaimInvalid.new("Missing required '#{field}' claim.") if !@decoded.key?(field.to_s)
        end
        raise ClaimInvalid.new("Missing required 'iat' claim.") if options.valid_within && !@decoded["iat"]
        raise ClaimInvalid.new("'iat' timestamp claim is too skewed from present.") if options.valid_within && (Time.now.to_i - @decoded["iat"]).abs > options.valid_within
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
        (params['username'].nil? || params['username'].empty? || params['password'].nil? || params['password'].empty?) && (params['token'].nil? || params['token'].empty?)
      end
    end

    class Jwt < JWT; end
  end
end
