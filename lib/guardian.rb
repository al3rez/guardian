# frozen_string_literal: true

require 'guardian/version'

module Guardian
  include ActionController::HttpAuthentication::Basic

  def token_valid?(email, password)
    return false if email.blank? || password.blank?

    User.find_by(email: email)&.authenticate(password)
  end

  def role_valid?(roles)
    roles_have_access = roles.map do |role|
      role_predicate = (role.to_s + '?').to_sym
      email, password = user_name_and_password(request)
      User.find_by(email: email)&.send(role_predicate)
    end

    roles_have_access.any?
  end

  def authenticate!
    raise BasicCredentialsMissing unless has_basic_credentials?(request)

    email, password = user_name_and_password(request)
    raise Unauthenticated unless token_valid?(email, password)
  end

  def authorize!(role)
    raise Unauthorized unless role_valid?(role)
  end

  def current_user
    email, password = user_name_and_password(request)
    User.find_by(email: email)
  end

  class Exception < StandardError
  end

  class Unauthorized < RuntimeError
    def to_s
      'Accessing the page or resource you were trying to reach is absolutely forbidden for some reason'
    end
  end

  class Unauthenticated < RuntimeError
    def to_s
      'The email address or password you provided is not correct'
    end
  end

  class BasicCredentialsMissing < Unauthenticated
    def to_s
      'Basic credentials are missing. The HTTP Authorization request header must contain basic credentials to authenticate a user.'
    end
  end
end
