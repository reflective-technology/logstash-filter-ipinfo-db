# encoding: utf-8
require_relative '../spec_helper'
require "logstash/filters/ipinfo-db"
require "fileutils"
require "tmpdir"
require "tempfile"
require "ipaddr"

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

  describe "database age warning" do
    let(:data_dir) { Dir.mktmpdir }
    let(:database) { File.join(data_dir, "ipinfo.mmdb").tap { |path| File.write(path, "x") } }
    after { FileUtils.rm_rf(data_dir) }

    def stub_db_built_days_ago(days)
      metadata = double("metadata", :build_epoch => Time.now.to_i - days * 86400)
      allow(MaxMind::DB).to receive(:new).and_return(double("db", :metadata => metadata))
    end

    it "warns when the database is older than database_age_warning_days" do
      stub_db_built_days_ago(45)
      plugin = described_class.new("source" => "ip", "database" => database)
      expect(plugin.logger).to receive(:warn).with(/outdated/, hash_including(:age_days => 45))
      plugin.register
    end

    it "does not warn for a recent database" do
      stub_db_built_days_ago(3)
      plugin = described_class.new("source" => "ip", "database" => database)
      expect(plugin.logger).not_to receive(:warn).with(/outdated/, anything)
      plugin.register
    end

    it "does not warn when disabled" do
      stub_db_built_days_ago(400)
      plugin = described_class.new("source" => "ip", "database" => database, "database_age_warning_days" => 0)
      expect(plugin.logger).not_to receive(:warn).with(/outdated/, anything)
      plugin.register
    end
  end

  describe "lookup results" do
    let(:data_dir) { Dir.mktmpdir }
    let(:database) { File.join(data_dir, "ipinfo.mmdb").tap { |path| File.write(path, "x") } }
    let(:db) { double("db", :metadata => double("metadata", :build_epoch => Time.now.to_i)) }
    let(:plugin) { described_class.new("source" => "ip", "database" => database) }
    after { FileUtils.rm_rf(data_dir) }

    before do
      allow(MaxMind::DB).to receive(:new).and_return(db)
      plugin.register
    end

    def run(fields)
      LogStash::Event.new(fields).tap { |event| plugin.filter(event) }
    end

    it "sets the target field when the IP is found" do
      allow(db).to receive(:get).with("8.8.8.8").and_return("country" => "US")
      event = run("ip" => "8.8.8.8")
      expect(event.get("[ipinfo-db][country]")).to eq("US")
      expect(event.get("tags")).to be_nil
    end

    it "leaves the event untouched when the IP is not in the database" do
      allow(db).to receive(:get).with("10.0.0.1").and_return(nil)
      event = run("ip" => "10.0.0.1")
      expect(event.get("ipinfo-db")).to be_nil
      expect(event.get("tags")).to be_nil
    end

    it "tags the event without a lookup when the source field is missing" do
      expect(db).not_to receive(:get)
      event = run("other" => "x")
      expect(event.get("tags")).to eq(["_ipinfo_db_lookup_failure"])
    end

    it "tags the event when the value is not a valid IP" do
      allow(db).to receive(:get).and_raise(IPAddr::InvalidAddressError, "invalid address: nope")
      event = run("ip" => "nope")
      expect(event.get("tags")).to eq(["_ipinfo_db_lookup_failure"])
    end

    it "logs unexpected errors and tags the event" do
      allow(db).to receive(:get).and_raise(RuntimeError, "boom")
      expect(plugin.logger).to receive(:warn).with(/Unexpected error/, hash_including(:message => "boom"))
      event = run("ip" => "1.2.3.4")
      expect(event.get("tags")).to eq(["_ipinfo_db_lookup_failure"])
    end
  end
end
