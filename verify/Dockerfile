ARG LOGSTASH_VERSION=9.5.5
FROM docker.elastic.co/logstash/logstash:${LOGSTASH_VERSION}
COPY plugin.gem /tmp/plugin.gem
# --no-verify: the gem is not on RubyGems yet; dependencies still resolve from RubyGems.
RUN bin/logstash-plugin install --no-verify /tmp/plugin.gem
COPY pipeline-token.conf pipeline-notoken.conf /usr/share/logstash/verify/
