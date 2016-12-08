#!/usr/bin/env ruby

require "yaml"
require "base64"
require "httparty"
require "aws-sdk"
require "sqlite3"
require "tempfile"

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

#
# API
#

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

def get_s3_token username, token, device_id, http
    response = http.post "#{API_URL}/GetS3Token",
                         {},
                         request_headers_with_auth(username, token, device_id)

    # TODO: Check for format errors
    status = response.parsed_response["SpcResponse"]["Status"].to_i

    if status != 0
        raise "S3 token request failed"
    end

    # TODO: Check for format errors and convert to some custom data struct
    response.parsed_response["SpcResponse"]["GetS3TokenResponse"]
end

#
# S3
#

def get_db_info s3, s3_token
    response = s3.get_object bucket: s3_token["BucketName"], key: "#{s3_token['ObjectPrefix']}1/spc.info"
    info = response.body.read

    {
        version: info[/VERSION\s+(\d+)/, 1],
        milestone: info[/MILESTONE\s+(\d+)/, 1]
    }
end

def get_db s3, s3_token, version
    response = s3.get_object bucket: s3_token["BucketName"], key: "#{s3_token['ObjectPrefix']}1/db_#{version}.dmp"
    Zlib::Inflate.inflate response.body.read
end

def get_latest_db s3_token
    credentials = Aws::Credentials.new s3_token["AccessKeyId"],
                                       s3_token["SecretAccessKey"],
                                       s3_token["SessionToken"]
    s3 = Aws::S3::Client.new region: "us-east-1",
                             credentials: credentials

    info = get_db_info s3, s3_token
    get_db s3, s3_token, info[:version]
end

#
# Crypto
#

def decrypt_aes_no_padding ciphertext, key
    c = OpenSSL::Cipher.new "aes-256-cbc"
    c.decrypt
    c.key = key
    c.iv = "\0" * 16
    c.padding = 0
    c.update(ciphertext) + c.final
end

def encrypt_aes plaintext, key
    c = OpenSSL::Cipher.new "aes-256-cbc"
    c.encrypt
    c.key = key
    c.iv = "\0" * 16
    c.update(plaintext) + c.final
end

def decrypt_aes ciphertext, key
    c = OpenSSL::Cipher.new "aes-256-cbc"
    c.decrypt
    c.key = key
    c.iv = "\0" * 16
    c.update(ciphertext) + c.final
end

def decrypt_text_entry ciphertext, key
    decrypt_aes(ciphertext, key)
        .encode(Encoding::UTF_8, Encoding::UTF_16LE)
        .chomp "\0"
end

def pbkdf_sha1 password, salt, iterations
    OpenSSL::PKCS5.pbkdf2_hmac_sha1 password, salt, iterations, 32
end

def derive_token_key username, password
    salt = Digest::MD5.digest username.downcase
    pbkdf_sha1 password, salt, 5000
end

def derive_db_key password, salt
    pbkdf_sha1 password, salt, 10000
end

def decrypt_token username, password, encrypted_token
    key = derive_token_key username, password
    decrypt_aes_no_padding encrypted_token, key
end

#
# sqlite
#

def sql db, query
    columns, *rows = db.execute2 query

    # Transform to an array of hashes.
    # Not very efficient but we don't have that many entries anyway.
    rows.map { |row| Hash[columns.zip row] }
end

User = Struct.new :id, :salt, :verification
Account = Struct.new :id, :name, :url, :notes, :credentials
Credentials = Struct.new :username, :passowrd, :description

def get_user_info db
    # "6400..." is "default\0" in UTF-16
    users = sql db, "select USER_ID, KEY, PASSWORD " +
                    "from USER " +
                    "where DATE_DELETED = 1 " +
                        "and USERNAME = x'640065006600610075006c0074000000'"
    raise "The default user is not found in the database" if users.empty?

    user = users[0]
    User.new user["USER_ID"], user["KEY"], user["PASSWORD"]
end

def derive_and_verify_db_key password, user
    key = derive_db_key password, user.salt

    verification = encrypt_aes "VERIFY", key
    raise "The master password is incorrect" if verification != user.verification

    key
end

def get_credentials_for_account db, user, account_id, key
    logins = sql db, "select LOG.UDC_USERNAME, LOG.UD_PASSWORD, LOG.UDC_DESCRIPTION " +
                     "from ACC_LOGIN LOG, ACC_LINK LINK " +
                     "where LINK.DATE_DELETED = 1 " +
                         "and LINK.USER_ID = #{user.id} " +
                         "and LINK.ENTRY_ID = #{account_id} " +
                         "and LOG.LOGIN_ID = LINK.LOGIN_ID " +
                     "order by LINK.LOGIN_ID"
    logins.map { |i|
        Credentials.new decrypt_text_entry(i["UDC_USERNAME"], key),
                        decrypt_text_entry(i["UD_PASSWORD"], key),
                        decrypt_text_entry(i["UDC_DESCRIPTION"], key)
    }
end

def get_accounts db, user, key
    # TODO: Why group type 2?
    accounts = sql db, "select ENTRY_ID, UDC_ENTRY_NAME, UDC_URL, UD_COMMENT " +
                       "from ACC_ACCOUNT " +
                       "where DATE_DELETED = 1 " +
                           "and USER_ID = #{user.id} " +
                           "and GROUP_TYPE = 2 " +
                       "order by ENTRY_ID"
    accounts.map { |i|
        id = i["ENTRY_ID"]
        Account.new id,
                    decrypt_text_entry(i["UDC_ENTRY_NAME"], key),
                    decrypt_text_entry(i["UDC_URL"], key),
                    decrypt_text_entry(i["UD_COMMENT"], key),
                    get_credentials_for_account(db, user, id, key)
    }
end

def parse_accounts filename, password
    SQLite3::Database.new filename do |db|
        user = get_user_info db
        key = derive_and_verify_db_key password, user
        return get_accounts db, user, key
    end
end

#
# main
#

config = YAML::load_file "config.yaml"

http = Http.new
encrypted_token = get_encrypted_token config["username"], config["device_id"], http
token = decrypt_token config["username"], config["password"], encrypted_token
authorize_device config["username"], token, config["device_id"], config["device_name"], http
s3_token = get_s3_token config["username"], token, config["device_id"], http
db = get_latest_db s3_token

# We need to save the database to an actual file on the disk.
# It doesn't seem to be possible to open a db from memory with
# sqlite3 Ruby bindings. The VFS interface is not exposed.
file = Tempfile.new "stickypassword-ruby"
file.write db
file.close

accounts = parse_accounts file.path, config["password"]
ap accounts
