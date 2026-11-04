# encoding: utf-8
require_relative '../spec_helper'
require "logstash/filters/ipinfo-db"
require "fileutils"
require "tmpdir"
require "tempfile"
require "ipaddr"

# Synthetic database with documentation networks only; see spec/fixtures/generate_ipinfo_test_mmdb.py.
FIXTURE_DATABASE = File.expand_path("../fixtures/ipinfo-test.mmdb", __dir__)

describe LogStash::Filters::IpinfoDb do
  after { described_class.clear_shared_readers }

  describe "shared database reader" do
    let(:data_dir) { Dir.mktmpdir }
    let(:database) { File.join(data_dir, "ipinfo.mmdb").tap { |path| FileUtils.cp(FIXTURE_DATABASE, path) } }
    after { FileUtils.rm_rf(data_dir) }

    def registered(path)
      described_class.new("source" => "ip", "database" => path, "database_age_warning_days" => 0).tap(&:register)
    end

    def reader(plugin)
      plugin.instance_variable_get(:@db)
    end

    it "loads a database file once for all filter instances" do
      expect(MaxMind::DB).to receive(:new).once.and_call_original
      first = registered(database)
      second = registered(database)
      expect(reader(second)).to equal(reader(first))

      event = LogStash::Event.new("ip" => "192.0.2.10")
      second.filter(event)
      expect(event.get("[ipinfo-db][country]")).to eq("US")
    end

    it "loads the file again after it is replaced" do
      first = registered(database)
      replacement = File.join(data_dir, "replacement.mmdb")
      FileUtils.cp(FIXTURE_DATABASE, replacement)
      File.rename(replacement, database)
      second = registered(database)
      expect(reader(second)).not_to equal(reader(first))
    end

    it "downloads a missing database once when filters start at the same time" do
      missing = File.join(data_dir, "downloaded.mmdb")
      allow(Down).to receive(:download) do
        sleep 0.5 # keep the first download in progress while the second filter registers
        Tempfile.new("ipinfo-download").tap do |file|
          file.binmode
          file.write(File.binread(FIXTURE_DATABASE))
          file.flush
        end
      end
      plugins = Array.new(2) do
        described_class.new("source" => "ip", "database" => missing, "token" => "t", "database_age_warning_days" => 0)
      end

      plugins.map { |plugin| Thread.new { plugin.register } }.each(&:join)

      expect(Down).to have_received(:download).once
      expect(reader(plugins[1])).to equal(reader(plugins[0]))
      expect(Dir.children(data_dir)).to eq(["downloaded.mmdb"])
    end

    it "evicts the reader when the last filter using it closes" do
      first = registered(database)
      second = registered(database)
      first.close
      expect(described_class.cached_reader(database)).to equal(reader(second))
      second.close
      expect(described_class.cached_reader(database)).to be_nil
    end

    it "evicts the old reader when a reload switches to another database path" do
      old = registered(database)
      versioned = File.join(data_dir, "ipinfo-v2.mmdb")
      FileUtils.cp(FIXTURE_DATABASE, versioned)
      current = registered(versioned)
      old.close
      expect(described_class.cached_reader(database)).to be_nil
      expect(described_class.cached_reader(versioned)).to equal(reader(current))
    end

    it "loads the file again if it is replaced while it is being loaded" do
      path = database
      loads = 0
      allow(MaxMind::DB).to receive(:new).and_wrap_original do |original, *args, **kwargs|
        loads += 1
        loaded = original.call(*args, **kwargs)
        if loads == 1 # an external updater replaces the file mid-load
          replacement = File.join(data_dir, "replacement.mmdb")
          FileUtils.cp(FIXTURE_DATABASE, replacement)
          File.rename(replacement, path)
        end
        loaded
      end

      registered(path)
      expect(loads).to eq(2)
      registered(path) # the cached identity matches the file now there, so no further load
      expect(loads).to eq(2)
    end

    it "loads the file again if it is replaced right after a download is moved into place" do
      target = File.join(data_dir, "downloaded.mmdb")
      allow(Down).to receive(:download) do
        Tempfile.new("ipinfo-download").tap do |file|
          file.binmode
          file.write(File.binread(FIXTURE_DATABASE))
          file.flush
        end
      end
      allow(File).to receive(:rename).and_wrap_original do |original, from, to|
        result = original.call(from, to)
        if to == target # an external updater rewrites it immediately
          File.binwrite(to, File.binread(FIXTURE_DATABASE))
          File.utime(Time.now, Time.now + 60, to)
        end
        result
      end
      expect(MaxMind::DB).to receive(:new).twice.and_call_original

      plugin = described_class.new("source" => "ip", "database" => target, "token" => "t", "database_age_warning_days" => 0)
      plugin.register
      expect(described_class.cached_reader(target)).to equal(reader(plugin))
    end

    it "keeps separate readers for different files" do
      other = File.join(data_dir, "other.mmdb")
      FileUtils.cp(FIXTURE_DATABASE, other)
      expect(reader(registered(other))).not_to equal(reader(registered(database)))
    end
  end

  describe "pipeline lookups against the fixture database" do
    config <<-CONFIG
      filter {
        ipinfo-db {
          source => "ip"
          database => "#{FIXTURE_DATABASE}"
          database_age_warning_days => 0
        }
      }
    CONFIG

    sample({ "ip" => "192.0.2.10" }) do
      expect(subject.get("ipinfo-db")).to eq(
        "country" => "US", "country_name" => "United States",
        "continent" => "NA", "continent_name" => "North America",
        "asn" => "AS64496", "as_name" => "Example Networks US", "as_domain" => "example.com"
      )
      expect(subject.get("tags")).to be_nil
    end

    sample({ "ip" => "198.51.100.7" }) do
      expect(subject.get("[ipinfo-db][country]")).to eq("JP")
      expect(subject.get("[ipinfo-db][asn]")).to eq("AS64497")
    end

    sample({ "ip" => "2001:db8::1" }) do
      expect(subject.get("[ipinfo-db][country]")).to eq("TW")
      expect(subject.get("[ipinfo-db][asn]")).to eq("AS64498")
    end

    # Valid but not in the database: left unchanged, not tagged.
    sample({ "ip" => "10.0.0.1" }) do
      expect(subject.get("ipinfo-db")).to be_nil
      expect(subject.get("tags")).to be_nil
    end

    sample({ "ip" => "not-an-ip" }) do
      expect(subject.get("ipinfo-db")).to be_nil
      expect(subject.get("tags")).to eq(["_ipinfo_db_lookup_failure"])
    end

    sample({ "other" => "no ip field" }) do
      expect(subject.get("ipinfo-db")).to be_nil
      expect(subject.get("tags")).to eq(["_ipinfo_db_lookup_failure"])
    end
  end

  describe "pipeline with custom target and tag_on_failure" do
    config <<-CONFIG
      filter {
        ipinfo-db {
          source => "[client][ip]"
          target => "[client][ipinfo]"
          tag_on_failure => ["no_ipinfo"]
          database => "#{FIXTURE_DATABASE}"
          database_age_warning_days => 0
        }
      }
    CONFIG

    sample({ "client" => { "ip" => "192.0.2.10" } }) do
      expect(subject.get("[client][ipinfo][country]")).to eq("US")
      expect(subject.get("ipinfo-db")).to be_nil
    end

    sample({ "client" => { "ip" => "bogus" } }) do
      expect(subject.get("tags")).to eq(["no_ipinfo"])
    end
  end

  describe "age warning with a real database" do
    let(:build_epoch) { MaxMind::DB.new(FIXTURE_DATABASE, mode: MaxMind::DB::MODE_MEMORY).metadata.build_epoch }

    it "uses the build time stored in the database" do
      plugin = described_class.new("source" => "ip", "database" => FIXTURE_DATABASE)
      allow(Time).to receive(:now).and_return(Time.at(build_epoch + 40 * 86400))
      expect(plugin.logger).to receive(:warn).with(/outdated/, hash_including(:age_days => 40))
      plugin.register
    end
  end

  # Downloads the real database from ipinfo.io. Excluded by default; run with
  #   IPINFO_TOKEN=... bundle exec rspec --tag integration
  describe "live ipinfo.io database", :integration => true do
    let(:data_dir) { Dir.mktmpdir }
    after { FileUtils.rm_rf(data_dir) }

    it "downloads the database and looks up a well-known IP" do
      skip("set IPINFO_TOKEN to run") if ENV["IPINFO_TOKEN"].to_s.empty?
      database = File.join(data_dir, "country_asn.mmdb")
      plugin = described_class.new("source" => "ip", "database" => database, "token" => ENV["IPINFO_TOKEN"])
      plugin.register
      expect(File.size(database)).to be > 0
      expect(Dir.children(data_dir)).to eq(["country_asn.mmdb"])

      event = LogStash::Event.new("ip" => "8.8.8.8")
      plugin.filter(event)
      expect(event.get("[ipinfo-db][country]")).to eq("US")
      expect(event.get("[ipinfo-db][asn]")).to eq("AS15169")
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
