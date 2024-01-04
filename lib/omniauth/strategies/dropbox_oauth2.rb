require 'omniauth-oauth2'

module OmniAuth
  module Strategies
    class DropboxOauth2 < OmniAuth::Strategies::OAuth2
      option :name, "dropbox_oauth2"
      option :client_options, {
        :site               => 'https://api.dropbox.com',
        :authorize_url      => 'https://www.dropbox.com/oauth2/authorize',
        :token_url          => 'https://www.dropbox.com/oauth2/token'
      }

      uid { raw_info.dig('admin_profile', 'account_id') || raw_info['account_id'] }

      info do
        {
          'uid'   => raw_info.dig('admin_profile', 'account_id') || raw_info['account_id'],
          'name'  => raw_info['name'] || raw_info.dig('admin_profile', 'name', 'display_name') || raw_info.dig('name', 'display_name'),
          'email' => raw_info.dig('admin_profile', 'email') || raw_info['email']
        }
      end

      extra do
        { 'raw_info' => raw_info }
      end

      def authorize_params
        super.tap do |params|
          params[:token_access_type] ||= 'offline'
        end
      end

      def raw_info
        return @raw_info if defined?(@raw_info)

        url = options[:client_options][:site]
        conn = Faraday.new(url: url) do |faraday|
          faraday.request  :url_encoded             # form-encode POST params
          faraday.response :logger                  # log requests to STDOUT
          faraday.adapter  Faraday.default_adapter  # make requests with Net::HTTP
        end
        response = conn.post do |req|
          req.url access_token.params['team_id'] ? '/2/team/token/get_authenticated_admin' : '/2/users/get_current_account'
          req.headers['Content-Type'] = 'application/json'
          req.headers['Authorization'] = "Bearer #{access_token.token}"
          req.body = "null"
        end

        @raw_info = MultiJson.decode(response.body)
      end

      def callback_url
        options.redirect_url || (full_host + callback_path)
      end
    end
  end
end
