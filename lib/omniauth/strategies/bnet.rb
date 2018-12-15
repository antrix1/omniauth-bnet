require 'omniauth-oauth2'
require 'base64'

module OmniauthStrategies
  class BattleNet < OmniAuth::Strategies::OAuth2
    option :client_options, {
      :scope => 'wow.profile'
    }

    def client(region)
      opts = options.client_options
      hostname = get_host(region)

      options.client_options[:authorize_url] = "https://#{hostname}/oauth/authorize" unless opts.has_key(:authorize_url)
      options.client_options[:token_url] = "https://#{hostname}/oauth/token" unless opts.has_key(:token_url)
      options.client_options[:site] = "https://#{hostname}/" unless opt.has_key(:site)

      super
    end

    def request_phase
      byebug
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

    private

    def callback_url
      full_host + script_name + callback_path
    end

    def get_host(region)
      region == 'cn' ? 'www.battlenet.com.cn' : '#{region}.battle.net'
    end
  end
end
