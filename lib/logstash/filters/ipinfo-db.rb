# encoding: utf-8
require "logstash/filters/base"
require 'down'
require 'maxmind/db'
require 'fileutils'
require 'securerandom'

# Looks up the country and ASN of an IP address in the ipinfo.io free country
# and ASN database (.mmdb) and stores the result in the event.
#
# filter {
#   ipinfo-db {
#     source => "ip"
#     token => "${IPINFO_TOKEN}"
#   }
# }
class LogStash::Filters::IpinfoDb < LogStash::Filters::Base

  DOWNLOAD_URL = "https://ipinfo.io/data/free/country_asn.mmdb"
  DEFAULT_FILE_NAME = "country_asn.mmdb"
  AGE_CHECK_INTERVAL = 24 * 60 * 60 # seconds

  config_name "ipinfo-db"

  # The field containing the IP address to look up. Hostnames are not resolved.
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

  # One in-memory reader per database file, shared by every filter instance in
  # the process (several ipinfo-db blocks, pipelines, config reloads), so the
  # database is held in the heap once. Readers are safe to use from multiple
  # threads.
  #
  # - Entries record the identity (inode, size, mtime) of the file they were
  #   loaded from, verified before and after loading, so a replaced file is
  #   loaded again by the next instance that registers.
  # - Entries are reference counted: register acquires, close releases, and the
  #   last release evicts the entry, so readers for files no filter uses any
  #   more (stopped pipelines, reloads to another database path) can be
  #   garbage collected.
  # - Setup for a given file (existence check, download, load, cache insert)
  #   runs under a per-path lock, so pipelines starting together download and
  #   load a missing database only once, while unrelated database files still
  #   set up in parallel. @registry_mutex only guards the hashes.
  @shared_readers = {}
  @path_locks = {}
  @registry_mutex = Mutex.new

  LOAD_ATTEMPTS = 3

  class << self
    def with_path_lock(path)
      lock = @registry_mutex.synchronize { @path_locks[path] ||= Mutex.new }
      lock.synchronize { yield }
    end

    # Acquire the cached reader for path if it was loaded from the file
    # currently there; nil otherwise.
    def acquire_reader(path)
      identity = file_identity(path)
      @registry_mutex.synchronize do
        entry = @shared_readers[path]
        next nil unless entry && entry[:identity] == identity
        entry[:refs] += 1
        entry[:reader]
      end
    end

    # Load path and cache the reader under the identity the file had for the
    # whole load. If the file is replaced while loading, load it again.
    def load_reader(path)
      LOAD_ATTEMPTS.times do
        before = file_identity(path)
        reader = MaxMind::DB.new(path, mode: MaxMind::DB::MODE_MEMORY)
        return store_reader(path, before, reader) if file_identity(path) == before
      end
      raise LogStash::ConfigurationError, "ipinfo-db: database file #{path} kept changing while it was being loaded"
    end

    # Cache reader (loaded from the file with identity) with one reference.
    def store_reader(path, identity, reader)
      @registry_mutex.synchronize { @shared_readers[path] = { :identity => identity, :reader => reader, :refs => 1 } }
      reader
    end

    # Drop one reference; evict the entry when no filter uses it any more. A
    # reader that was already superseded by a newer file is not in the cache.
    def release_reader(path, reader)
      @registry_mutex.synchronize do
        entry = @shared_readers[path]
        next unless entry && entry[:reader].equal?(reader)
        entry[:refs] -= 1
        @shared_readers.delete(path) if entry[:refs] <= 0
      end
    end

    # The cached reader for path, if any (no reference taken). For specs.
    def cached_reader(path)
      @registry_mutex.synchronize { @shared_readers[File.expand_path(path)] }&.fetch(:reader)
    end

    # For specs.
    def clear_shared_readers
      @registry_mutex.synchronize { @shared_readers.clear }
    end

    def file_identity(path)
      stat = File.stat(path)
      [stat.ino, stat.size, stat.mtime.to_r]
    end
  end

  def register
    setup_database
    check_database_age
  end

  def close
    self.class.release_reader(@database, @db) if @db
    @db = nil
  end

  def filter(event)
    next_age_check = @next_age_check
    check_database_age if next_age_check && Time.now >= next_age_check
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

    # Not in the database (e.g. private ranges): not an error, leave the event as is.
    if record.nil?
      @logger.debug? && @logger.debug("IP not found in the ipinfo database", :ip => ip)
      return
    end

    begin
      event.set(@target, record)
      filter_matched(event)
    rescue => e
      @logger.warn("Unexpected error during ipinfo enrichment", :ip => ip, :exception => e.class.name, :message => e.message)
      tag_unsuccessful_lookup(event, e.message)
    end
  end

  def tag_unsuccessful_lookup(event, reason)
    @logger.debug? && @logger.debug("ipinfo lookup failed", :ip => event.get(@source), :reason => reason)
    @tag_on_failure.each{|tag| event.tag(tag)}
  end

  # Download .mmdb file and load it into mmdb reader
  def setup_database
    # Normalize once (expands ~ and makes relative paths absolute) so the existence
    # check, download, rename and reader cache all use the same path.
    @database = File.expand_path(@database || default_database_path)
    path = @database

    @db = self.class.with_path_lock(path) do
      if File.exist?(path)
        self.class.acquire_reader(path) || self.class.load_reader(path)
      else
        if @token.nil? || @token.value.to_s.empty?
          raise LogStash::ConfigurationError, "ipinfo-db: database file #{@database} not found. Set `token` to download it, or place the file there."
        end
        reader, identity = download_database
        # A rename keeps inode, size and mtime, so a different identity here means
        # another process replaced the file after our rename: load what is there.
        if File.exist?(path) && self.class.file_identity(path) == identity
          self.class.store_reader(path, identity, reader)
        else
          self.class.load_reader(path)
        end
      end
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
  # several pipelines download at the same time. Returns the reader and the
  # identity of the file it was loaded from.
  def download_database
    @logger.info("Downloading ipinfo database", :path => @database)
    dir = File.dirname(@database)
    FileUtils.mkdir_p(dir)
    tmp_path = File.join(dir, ".#{File.basename(@database)}.#{SecureRandom.hex(8)}.tmp")

    tempfile = Down.download("#{DOWNLOAD_URL}?token=#{@token.value}")
    FileUtils.mv(tempfile.path, tmp_path)
    begin
      db = MaxMind::DB.new(tmp_path, mode: MaxMind::DB::MODE_MEMORY)
    rescue MaxMind::DB::InvalidDatabaseError => e
      raise LogStash::ConfigurationError, "ipinfo-db: downloaded database is not a valid .mmdb file: #{e.message}"
    end
    identity = self.class.file_identity(tmp_path) # only this process writes tmp_path
    File.rename(tmp_path, @database)
    [db, identity]
  ensure
    FileUtils.rm_f(tmp_path) if tmp_path
  end

  # Keep the downloaded database under Logstash's data directory, which is
  # writable by the logstash user and persists across restarts.
  def default_database_path
    File.join(LogStash::SETTINGS.get_value("path.data"), "plugins", "filters", "ipinfo-db", DEFAULT_FILE_NAME)
  end

end # class LogStash::Filters::IpinfoDb
