## Unreleased

  - Faster lookups of private IPv4 addresses. When it loads a database, the plugin
    now indexes the IPv4 /16 blocks that hold no data (private, reserved and unused ranges; built
    from the database itself, about a second per file) and answers lookups in them without
    searching the database. In a benchmark with four lookups per event on private addresses
    (Logstash 9.5, 2 CPUs, 4 workers), throughput went from about 78k to 265k events/s, more than
    skipping the lookups with a `ruby` filter in front (116k)
  - Values that cannot be IP addresses (for example `-` or `unknown`) are tagged without raising an
    exception inside the lookup: about 18k to 250k events/s in the same benchmark
  - IPv4 addresses are parsed by the plugin instead of `IPAddr`; lookups of public addresses are
    unchanged or slightly faster

## 0.4.0

  - Recover from an existing invalid database file (for example truncated or empty): with `token`
    set, log a warning and download a fresh copy; without it, fail with a message saying to delete or
    replace the file (#3)

## 0.3.0

  - Declare `required_ruby_version >= 3.1` in the gemspec. Logstash 8.19 (JRuby 9.4, Ruby 3.1
    compatible) is the oldest runtime verified in CI; Logstash 9.x ships JRuby 10.

## 0.2.0

  - Forked as `logstash-filter-ipinfo-db-zuin` (filter name stays `ipinfo-db`)
  - Add `token` setting; the ipinfo.io token is no longer hardcoded
  - Add `database` setting. The database is now stored at
    `<path.data>/plugins/filters/ipinfo-db/country_asn.mmdb` by default instead of the
    Logstash working directory, which is `/` (not writable) under the deb/rpm systemd service
  - Validate the downloaded database before atomically moving it into place, so an interrupted
    or invalid download no longer leaves a broken file that blocks every later start
  - Add `database_age_warning_days` (default 30): log a warning at startup and once a day
    when the database is older than that
  - Handle IPs not in the database and missing source fields without raising exceptions
    (faster on JRuby); log unexpected lookup errors as warnings instead of swallowing them
  - IPs that are valid but not in the database are no longer tagged with `tag_on_failure`;
    the event is left unchanged
  - Filters that use the same database file share one in-memory copy instead of loading one
    each (several `ipinfo-db` blocks, pipelines, config reloads)
  - Pin `down` to `~> 5.2` (compatible with `logstash-core`, which requires `down ~> 5.2.0`)
    and `maxmind-db` to `~> 1.2`
  - Docs: README now documents installation and settings; `source` docs no longer claim hostname
    support; package `docs/` and no longer package `vendor/`

## 0.1.0

  - Plugin created with the logstash plugin generator
  - Initial devlopment
  - Test case for plugin
  - Documentation
  - Review Preparation

