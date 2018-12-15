require 'omniauth-oauth2'
require 'oauth2'
require 'base64'

module OmniAuth
  module Strategies
    class Bnet < OmniAuth::Strategies::OAuth2
      attr_accessor :region

      option :client_options, {
        :scope => 'wow.profile'
      }

      def client
        opts = options.client_options
        hostname = host_for(region)
        puts "HOSTNAME IS #{hostname}"

        options.client_options[:authorize_url] = "https://#{hostname}/oauth/authorize"
        options.client_options[:token_url] = "https://#{hostname}/oauth/token"
        options.client_options[:site] = "https://#{hostname}/"

        byebug
        super
      end

      def request_phase
        @region = request.params['region']
        super
      end

      def authorize_params
        super.tap do |params|
          %w[scope client_options].each do |v|
            if request.params[v]
              params[v.to_sym] = request.params[v]
            end
          end
        end
      end

      uid { raw_info['id'].to_s }

      info do
        raw_info
      end

      def raw_info
        return @raw_info if @raw_info

        access_token.options[:mode] = :query

        @raw_info = access_token.get('oauth/userinfo').parsed
      end

      def callback_phase
        byebug
        super
      end

      private

      def callback_url
        full_host + script_name + callback_path
      end

      def host_for(region)
        region == 'cn' ? 'www.battlenet.com.cn' : "#{region}.battle.net"
      end
    end
  end
end
