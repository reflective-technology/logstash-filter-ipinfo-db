## 0.2.0

  - Forked as `logstash-filter-ipinfo-db-zuin` (filter name stays `ipinfo-db`)
  - Add `token` setting; the ipinfo.io token is no longer hardcoded
  - Add `database` setting. The database is now stored at
    `<path.data>/plugins/filters/ipinfo-db/country_asn.mmdb` by default instead of the
    Logstash working directory, which is `/` (not writable) under the deb/rpm systemd service
  - Validate the downloaded database before atomically moving it into place, so an interrupted
    or invalid download no longer leaves a broken file that blocks every later start
  - Pin `down` to `~> 5.4` and `maxmind-db` to `~> 1.2`

## 0.1.0

  - Plugin created with the logstash plugin generator
  - Initial devlopment
  - Test case for plugin
  - Documentation
  - Review Preparation

