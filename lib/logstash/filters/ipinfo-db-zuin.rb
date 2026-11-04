# encoding: utf-8
require "logstash/filters/base"
require 'down'
require 'maxmind/db'

$MMDB_FILE_DOWNLOAD_URL = "https://ipinfo.io/data/free/country_asn.mmdb?token=c0c038dbe0e4e7"
$MMDB_FILE_NAME = "country_asn.mmdb"

# This ipinfo-db-zuin filter will replace the contents of the default
# message field with whatever you specify in the configuration.
#
# It is only intended to be used as an ipinfo-db-zuin.
class LogStash::Filters::IpinfoDbZuin < LogStash::Filters::Base

  # Setting the config_name here is required. This is how you
  # configure this filter from your Logstash config.
  #
  # filter {
  #   ipinfo-db-zuin {
  #      source => "ip"
  #   }
  # }
  #
  config_name "ipinfo-db-zuin"

  # The field containing the IP address or hostname to map via ipinfo.io. 
  config :source, :validate => :string, :required => true

  # The field to write the lookup results into. If not specified, the default
  # value will be used.
  config :target, :validate => :string, :default => "ipinfo-db"

  # Tags the event on failure to look up ipinfo information. This can be used in later analysis.
  # If not specified, the default value will be used.
  config :tag_on_failure, :validate => :array, :default => ["_ipinfo_db_lookup_failure"]

  public
  def register
    setup_database
  end # def register

  public
  def filter(event)
    @logger.debug? && @logger.debug("Running ipinfo-db-zuin lookup", :event => event)
    ip = event.get(@source)

    begin
      ret = @db.get(ip)
      event.set(@target, ret.to_hash)
      filter_matched(event)
    rescue => e
      tag_unsuccessful_lookup(event)
    end
  end

  def tag_unsuccessful_lookup(event)
    @logger.debug? && @logger.debug("IP #{event.get(@source)} was not found in the database", :event => event)
    @tag_on_failure.each{|tag| event.tag(tag)}
  end

  # Download .mmdb file and load it into mmdb reader
  def setup_database
    # Download mmdb file from ipinfo.io if not found
    if !File.exist?($MMDB_FILE_NAME)
      tempfile = Down.download($MMDB_FILE_DOWNLOAD_URL)
      FileUtils.mv(tempfile.path, "./#{tempfile.original_filename}")
    end
    # Load .mmdb file in MaxMindDB reader
    @db = MaxMind::DB.new($MMDB_FILE_NAME, mode: MaxMind::DB::MODE_MEMORY)
  end

end # class LogStash::Filters::IpinfoDbZuin
