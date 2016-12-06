#!/usr/bin/env ruby

require "yaml"
require "base64"
require "httparty"

API_URL = "https://spcb.stickypassword.com/SPCClient"

# Set to true to redirect everything but S3 to a local mitmproxy instance
USE_PROXY = false

class Http
    include HTTParty

    def initialize
        @options = {
            verify: false
        }

        if USE_PROXY
            @options[:http_proxyaddr] = "localhost"
            @options[:http_proxyport] = 9999
        end

        @post_headers = {
        }
    end

    def get url, headers = {}
        self.class.get url, @options.merge({
            headers: headers
        })
    end

    def post url, args, headers = {}
        self.class.post url, @options.merge({
            body: args,
            headers: @post_headers.merge(headers)
        })
    end
end

# Base64 encoding
class String
    def to_64
        Base64.strict_encode64 self
    end

    def from_64
        Base64.strict_decode64 self
    end
end

def request_headers device_id
    {
        "User-Agent" => "SP/8.0.3436 Prot=2 ID=#{device_id} Lng=EN Os=Android/4.4.4 Lic= LicStat= PackageID=",
        "Date" => "#{Time.now.httpdate}",
        "Accept" => "application/xml",
        "Pragma" => "no-cache",
        "Cache-Control" => "no-cache",
        "Content-Type" => "application/x-www-form-urlencoded; charset=UTF-8",
        "host" => "spcb.stickypassword.com",
        "Connection" => "Keep-Alive",
        "Accept-Encoding" => "gzip",
    }
end

def request_headers_with_auth username, token, device_id
    auth = "#{username}:#{token.to_64}".to_64
    request_headers(device_id).merge({"Authorization" => "Basic #{auth}"})
end

def get_encrypted_token username, device_id, http
    response = http.post "#{API_URL}/GetCrpToken", {uaid: username}, request_headers(device_id)

    # TODO: Check for format errors
    response.parsed_response["SpcResponse"]["GetCrpTokenResponse"]["CrpToken"].from_64
end

def authorize_device username, token, device_id, device_name, http
    response = http.post "#{API_URL}/DevAuth",
                         {hid: device_name},
                         request_headers_with_auth(username, token, device_id)

    # TODO: Check for format errors
    status = response.parsed_response["SpcResponse"]["Status"].to_i

    # Looks like:
    #  - 0 means the new device has been registered
    #  - 4005 means all is good and the device is there already
    # TODO: There's more logic in the executable. Check what it's for.
    if status != 0 && status != 4005
        raise "Device authorization failed"
    end
end

def decrypt_aes_no_padding ciphertext, key, iv
    c = OpenSSL::Cipher.new "aes-256-cbc"
    c.decrypt
    c.key = key
    c.iv = iv
    c.padding = 0
    c.update(ciphertext) + c.final
end

def derive_token_key username, password
    salt = Digest::MD5.digest username.downcase
    OpenSSL::PKCS5.pbkdf2_hmac_sha1 password, salt, 5000, 32
end

def decrypt_token username, password, encrypted_token
    key = derive_token_key username, password
    decrypt_aes_no_padding encrypted_token, key, "\0" * 16
end

#
# main
#

config = YAML::load_file "config.yaml"

http = Http.new
encrypted_token = get_encrypted_token config["username"], config["device_id"], http
token = decrypt_token config["username"], config["password"], encrypted_token
authorize_device config["username"], token, config["device_id"], config["device_name"], http
