# encoding: utf-8
require "logstash/filters/base"
require 'down'
require 'maxmind/db'
require 'fileutils'
require 'securerandom'

$MMDB_FILE_DOWNLOAD_URL = "https://ipinfo.io/data/free/country_asn.mmdb"
$MMDB_FILE_NAME = "country_asn.mmdb"

# This ipinfo-db filter will replace the contents of the default
# message field with whatever you specify in the configuration.
#
# It is only intended to be used as an ipinfo-db.
class LogStash::Filters::IpinfoDb < LogStash::Filters::Base

  # Setting the config_name here is required. This is how you
  # configure this filter from your Logstash config.
  #
  # filter {
  #   ipinfo-db {
  #      source => "ip"
  #   }
  # }
  #
  config_name "ipinfo-db"

  # The field containing the IP address or hostname to map via ipinfo.io. 
  config :source, :validate => :string, :required => true

  # The field to write the lookup results into. If not specified, the default
  # value will be used.
  config :target, :validate => :string, :default => "ipinfo-db"

  # Tags the event on failure to look up ipinfo information. This can be used in later analysis.
  # If not specified, the default value will be used.
  config :tag_on_failure, :validate => :array, :default => ["_ipinfo_db_lookup_failure"]

  # ipinfo.io access token used to download the database. Only needed when
  # the file at `database` does not exist yet. Use ${IPINFO_TOKEN} to read it
  # from an environment variable or the Logstash keystore.
  config :token, :validate => :password

  # Path to the ipinfo .mmdb database file. If the file does not exist, it is
  # downloaded to this path using `token`. Defaults to
  # <path.data>/plugins/filters/ipinfo-db/country_asn.mmdb.
  config :database, :validate => :string

  # Log a warning when the database was built more than this many days ago.
  # Checked at startup and then once a day. Set to 0 to disable.
  config :database_age_warning_days, :validate => :number, :default => 30

  AGE_CHECK_INTERVAL = 24 * 60 * 60 # seconds

  public
  def register
    setup_database
    check_database_age
  end # def register

  public
  def filter(event)
    check_database_age if @next_age_check && Time.now >= @next_age_check
    @logger.debug? && @logger.debug("Running ipinfo-db lookup", :event => event)
    ip = event.get(@source)

    # Misses are common (private IPs, missing fields), so handle them without
    # raising: exceptions are expensive in JRuby.
    if ip.nil? || ip == ""
      tag_unsuccessful_lookup(event, "source field is empty")
      return
    end

    begin
      record = @db.get(ip)
    rescue ArgumentError => e
      # Not a valid IP address (IPAddr errors are ArgumentErrors), or an IPv6
      # address looked up in an IPv4-only database.
      tag_unsuccessful_lookup(event, e.message)
      return
    rescue => e
      @logger.warn("Unexpected error during ipinfo lookup", :ip => ip, :exception => e.class.name, :message => e.message)
      tag_unsuccessful_lookup(event, e.message)
      return
    end

    if record.nil?
      tag_unsuccessful_lookup(event, "not found in the database")
      return
    end

    event.set(@target, record)
    filter_matched(event)
  end

  def tag_unsuccessful_lookup(event, reason)
    @logger.debug? && @logger.debug("ipinfo lookup failed", :ip => event.get(@source), :reason => reason)
    @tag_on_failure.each{|tag| event.tag(tag)}
  end

  # Download .mmdb file and load it into mmdb reader
  def setup_database
    @database ||= default_database_path

    if File.exist?(@database)
      @db = MaxMind::DB.new(@database, mode: MaxMind::DB::MODE_MEMORY)
    else
      if @token.nil? || @token.value.to_s.empty?
        raise LogStash::ConfigurationError, "ipinfo-db: database file #{@database} not found. Set `token` to download it, or place the file there."
      end
      @db = download_database
    end
  end

  private

  # Warn when the loaded database is older than database_age_warning_days,
  # based on the build time stored in the database itself.
  def check_database_age
    @next_age_check = nil
    return if @database_age_warning_days <= 0

    build_epoch = @db.metadata.build_epoch
    return if build_epoch.nil?

    @next_age_check = Time.now + AGE_CHECK_INTERVAL
    age_days = ((Time.now.to_i - build_epoch) / 86400.0).floor
    if age_days > @database_age_warning_days
      @logger.warn("ipinfo database is outdated; lookups may be inaccurate. " \
                   "Delete the file to download a fresh copy on the next start (requires `token`), or replace it",
                   :path => @database, :age_days => age_days, :built_at => Time.at(build_epoch).utc.to_s,
                   :database_age_warning_days => @database_age_warning_days)
    end
  end

  # Download into a temp file next to @database, check that it is a readable
  # database, then rename it into place. The rename is atomic, so @database is
  # never a partial or invalid file, even if the download is interrupted or
  # several pipelines download at the same time.
  def download_database
    @logger.info("Downloading ipinfo database", :path => @database)
    dir = File.dirname(@database)
    FileUtils.mkdir_p(dir)
    tmp_path = File.join(dir, ".#{File.basename(@database)}.#{SecureRandom.hex(8)}.tmp")

    tempfile = Down.download("#{$MMDB_FILE_DOWNLOAD_URL}?token=#{@token.value}")
    FileUtils.mv(tempfile.path, tmp_path)
    begin
      db = MaxMind::DB.new(tmp_path, mode: MaxMind::DB::MODE_MEMORY)
    rescue MaxMind::DB::InvalidDatabaseError => e
      raise LogStash::ConfigurationError, "ipinfo-db: downloaded database is not a valid .mmdb file: #{e.message}"
    end
    File.rename(tmp_path, @database)
    db
  ensure
    FileUtils.rm_f(tmp_path) if tmp_path
  end

  # Keep the downloaded database under Logstash's data directory, which is
  # writable by the logstash user and persists across restarts.
  def default_database_path
    File.join(LogStash::SETTINGS.get_value("path.data"), "plugins", "filters", "ipinfo-db", $MMDB_FILE_NAME)
  end

end # class LogStash::Filters::IpinfoDb
