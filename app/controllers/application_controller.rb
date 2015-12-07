require 'digest'

class ApplicationController < ActionController::Base
  # Prevent CSRF attacks by raising an exception.
  # For APIs, you may want to use :null_session instead.
  protect_from_forgery with: :null_session

  after_filter  :set_access_control_headers
  before_filter :authorize_api_request!
  def set_access_control_headers 
    headers['Access-Control-Allow-Origin'] = '*' 
    headers['Access-Control-Request-Method'] = '*'
  end

  private


  def authorize_api_request!
  	if params[:format].to_s == 'json'
  		# Prevent unauthorized requests
      t = Time.now.to_i
      token = Digest::SHA256.hexdigest("#{t}k1tten_m1tt3ns")
      if params[:token] != token 
        render json: {}, status: :forbidden 
      end
  	end
  end
end
