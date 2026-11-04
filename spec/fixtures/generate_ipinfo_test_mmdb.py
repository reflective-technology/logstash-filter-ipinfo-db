"""Generate spec/fixtures/ipinfo-test.mmdb, a tiny database for offline specs.

It uses the field layout of the ipinfo.io free country_asn database, but only documentation
networks (RFC 5737, RFC 3849) and documentation ASNs (RFC 5398), so its data is synthetic.

Regenerate from the repository root with:

  docker run --rm -v "$PWD/spec/fixtures":/fixtures python:3.12-slim sh -c \
    'pip install -q mmdb-writer==0.2.7 netaddr==1.3.0 && python /fixtures/generate_ipinfo_test_mmdb.py'

Keep this data in sync with spec/filters/ipinfo-db_spec.rb.
"""
from netaddr import IPSet
from mmdb_writer import MMDBWriter

RECORDS = {
    "192.0.2.0/24": {
        "country": "US",
        "country_name": "United States",
        "continent": "NA",
        "continent_name": "North America",
        "asn": "AS64496",
        "as_name": "Example Networks US",
        "as_domain": "example.com",
    },
    "198.51.100.0/24": {
        "country": "JP",
        "country_name": "Japan",
        "continent": "AS",
        "continent_name": "Asia",
        "asn": "AS64497",
        "as_name": "Example Networks JP",
        "as_domain": "example.jp",
    },
    "2001:db8::/32": {
        "country": "TW",
        "country_name": "Taiwan",
        "continent": "AS",
        "continent_name": "Asia",
        "asn": "AS64498",
        "as_name": "Example Networks TW",
        "as_domain": "example.tw",
    },
}

writer = MMDBWriter(
    ip_version=6,
    ipv4_compatible=True,
    database_type="ipinfo country_asn.mmdb",
    languages=["en"],
    description="Synthetic test database for logstash-filter-ipinfo-db-zuin specs",
)
for network, record in RECORDS.items():
    writer.insert_network(IPSet([network]), record)
writer.to_db_file("/fixtures/ipinfo-test.mmdb")
print("wrote /fixtures/ipinfo-test.mmdb")
