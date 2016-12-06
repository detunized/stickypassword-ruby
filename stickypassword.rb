#!/usr/bin/env ruby

require "yaml"
require "httparty"

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

config = YAML::load_file "config.yaml"
