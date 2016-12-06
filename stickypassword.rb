#!/usr/bin/env ruby

require "yaml"
require "httparty"

config = YAML::load_file "config.yaml"
