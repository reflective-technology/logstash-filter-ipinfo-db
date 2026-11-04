# encoding: utf-8
require_relative '../spec_helper'
require "logstash/filters/ipinfo-db"

describe LogStash::Filters::IpinfoDb do
  describe "ipinfo lookup test" do
    config <<-CONFIG
      filter {
        ipinfo-db {
          source => "ip"
        }
      }
    CONFIG

    sample("ip" => "173.9.34.107") do
      expect(subject.get("[ipinfo-db][country]")).to eq('US')
    end
  end
end
