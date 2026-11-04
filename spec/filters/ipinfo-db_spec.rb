# encoding: utf-8
require_relative '../spec_helper'
require "logstash/filters/ipinfo-db"
require "fileutils"
require "tmpdir"
require "tempfile"

describe LogStash::Filters::IpinfoDb do
  describe "ipinfo lookup test" do
    config <<-CONFIG
      filter {
        ipinfo-db {
          source => "ip"
          token => "#{ENV['IPINFO_TOKEN']}"
        }
      }
    CONFIG

    sample("ip" => "173.9.34.107") do
      expect(subject.get("[ipinfo-db][country]")).to eq('US')
    end
  end

  describe "database location" do
    let(:data_dir) { Dir.mktmpdir }
    after { FileUtils.rm_rf(data_dir) }

    it "defaults to a file under path.data" do
      allow(LogStash::SETTINGS).to receive(:get_value).and_call_original
      allow(LogStash::SETTINGS).to receive(:get_value).with("path.data").and_return(data_dir)
      expected = File.join(data_dir, "plugins", "filters", "ipinfo-db", "country_asn.mmdb")
      plugin = described_class.new("source" => "ip")
      expect { plugin.register }.to raise_error(LogStash::ConfigurationError, /#{Regexp.escape(expected)}/)
    end

    it "uses the configured database path" do
      missing = File.join(data_dir, "missing.mmdb")
      plugin = described_class.new("source" => "ip", "database" => missing)
      expect { plugin.register }.to raise_error(LogStash::ConfigurationError, /#{Regexp.escape(missing)}/)
    end

    it "does not keep an invalid download" do
      bad = Tempfile.new("bad-mmdb")
      bad.write("not a database")
      bad.flush
      allow(Down).to receive(:download).and_return(bad)
      database = File.join(data_dir, "ipinfo.mmdb")
      plugin = described_class.new("source" => "ip", "database" => database, "token" => "t")
      expect { plugin.register }.to raise_error(LogStash::ConfigurationError, /not a valid \.mmdb/)
      expect(Dir.children(data_dir)).to be_empty
    end
  end
end
