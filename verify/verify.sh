#!/usr/bin/env bash
# Verify logstash-filter-ipinfo-db-zuin on the official Logstash Docker image.
#
# Usage:
#   export IPINFO_TOKEN=...            # optional: your ipinfo.io token
#   verify/verify.sh [logstash-version]
#
# Steps 1-4 install the gem and run real pipelines; step 5 runs the RSpec suite on Logstash's JRuby.
# Without IPINFO_TOKEN (e.g. CI on pull requests from forks), the checks that download the live
# database (steps 2-3 and the integration spec) are reported as SKIP; everything else still runs.
set -uo pipefail

KIT=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$KIT/.." && pwd)
LS_VERSION=${1:-9.5.5}
IMAGE=ipinfo-db-verify:$LS_VERSION
VOLUME=ipinfo-db-verify-data
OUT=$KIT/out
mkdir -p "$OUT"
IPINFO_TOKEN=${IPINFO_TOKEN:-}
export IPINFO_TOKEN

results=()
record() { results+=("$1 $2"); echo "==> $1 $2"; }

# Run a pipeline the way the deb/rpm systemd service does: non-root user (the image runs as
# uid 1000), working directory "/".
run_pipeline() { # <volume> <pipeline file> <output file> [extra docker args...]
  local vol=$1 conf=$2 out=$3; shift 3
  docker run --rm -w / -e XPACK_MONITORING_ENABLED=false "$@" \
    -v "$vol":/usr/share/logstash/data "$IMAGE" \
    -f "/usr/share/logstash/verify/$conf" >"$out" 2>&1
}

echo "### 1. Build the gem and install it into Logstash $LS_VERSION"
(cd "$REPO" && gem build logstash-filter-ipinfo-db-zuin.gemspec --output "$KIT/plugin.gem") \
  && docker build --build-arg LOGSTASH_VERSION="$LS_VERSION" -t "$IMAGE" "$KIT" >"$OUT/1-build.log" 2>&1 \
  && docker run --rm --entrypoint bin/logstash-plugin "$IMAGE" list --verbose ipinfo >"$OUT/1-list.log" 2>&1 \
  && GEM_VERSION=$(cd "$REPO" && ruby -e 'puts Gem::Specification.load("logstash-filter-ipinfo-db-zuin.gemspec").version') \
  && grep -qF "logstash-filter-ipinfo-db-zuin ($GEM_VERSION)" "$OUT/1-list.log"
[ $? -eq 0 ] && record PASS "install (see out/1-list.log)" || record FAIL "install (see out/1-build.log, out/1-list.log)"

if [ -z "$IPINFO_TOKEN" ]; then
  echo "### 2-3. Skipped: IPINFO_TOKEN is not set"
  record SKIP "live download, lookups and restart (IPINFO_TOKEN not set)"
else
echo "### 2. First start with token: download to path.data, lookups"
docker volume rm -f "$VOLUME" >/dev/null 2>&1
run_pipeline "$VOLUME" pipeline-token.conf "$OUT/2-first-start.log" -e IPINFO_TOKEN
grep -q 'Downloading ipinfo database.*/usr/share/logstash/data/plugins/filters/ipinfo-db/country_asn.mmdb' "$OUT/2-first-start.log" \
  && record PASS "downloaded to path.data with working dir / as non-root" \
  || record FAIL "download log line not found (see out/2-first-start.log)"
python3 -I "$KIT/check_events.py" "$OUT/2-first-start.log" | tee "$OUT/2-events.txt"
[ "${PIPESTATUS[0]}" -eq 0 ] && record PASS "lookup results" || record FAIL "lookup results (see out/2-events.txt)"
docker run --rm --entrypoint ls -v "$VOLUME":/data "$IMAGE" -la /data/plugins/filters/ipinfo-db >"$OUT/2-files.txt" 2>&1
if grep -q 'country_asn.mmdb$' "$OUT/2-files.txt" && ! grep -q '\.tmp$' "$OUT/2-files.txt"; then
  record PASS "database file present, no temp files left"
else
  record FAIL "database dir contents (see out/2-files.txt)"
fi
grep -q 'outdated' "$OUT/2-first-start.log" \
  && record FAIL "fresh database reported as outdated" || record PASS "no outdated warning for a fresh database"

echo "### 3. Restart without token: reuse the downloaded file"
run_pipeline "$VOLUME" pipeline-notoken.conf "$OUT/3-restart.log"
if ! grep -q 'Downloading ipinfo database' "$OUT/3-restart.log" && python3 -I "$KIT/check_events.py" "$OUT/3-restart.log" >"$OUT/3-events.txt"; then
  record PASS "restart reuses database, no download, no token needed"
else
  record FAIL "restart (see out/3-restart.log, out/3-events.txt)"
fi
fi

echo "### 4. Empty data dir and no token: clear startup error"
docker volume rm -f "$VOLUME-empty" >/dev/null 2>&1
run_pipeline "$VOLUME-empty" pipeline-notoken.conf "$OUT/4-no-token.log"
grep -q 'database file /usr/share/logstash/data/plugins/filters/ipinfo-db/country_asn.mmdb not found. Set `token`' "$OUT/4-no-token.log" \
  && record PASS "missing database without token fails with a clear message" \
  || record FAIL "no-token error message not found (see out/4-no-token.log)"
docker volume rm -f "$VOLUME-empty" >/dev/null 2>&1

echo "### 5. RSpec on Logstash's JRuby"
# bin/logstash adds these JVM flags itself (JvmOptionsParser); calling jruby directly needs them too,
# or the pipeline compiler fails with IllegalAccessError on jdk.compiler.
JVM_FLAGS="--add-exports=jdk.compiler/com.sun.tools.javac.api=ALL-UNNAMED
--add-exports=jdk.compiler/com.sun.tools.javac.file=ALL-UNNAMED
--add-exports=jdk.compiler/com.sun.tools.javac.parser=ALL-UNNAMED
--add-exports=jdk.compiler/com.sun.tools.javac.tree=ALL-UNNAMED
--add-exports=jdk.compiler/com.sun.tools.javac.util=ALL-UNNAMED
--add-opens=java.base/java.security=ALL-UNNAMED
--add-opens=java.base/java.io=ALL-UNNAMED
--add-opens=java.base/java.nio.channels=ALL-UNNAMED
--add-opens=java.base/sun.nio.ch=ALL-UNNAMED
--add-opens=java.management/sun.management=ALL-UNNAMED"
# The checkout is mounted read-only and copied, because the container user (uid 1000) may not be
# able to write to it (e.g. on Linux CI runners) and bundler writes Gemfile.lock next to the Gemfile.
docker run --rm -v "$REPO":/plugin:ro \
  -e LOGSTASH_PATH=/usr/share/logstash -e BUNDLE_PATH=/tmp/bundle -e IPINFO_TOKEN \
  -e JAVA_HOME=/usr/share/logstash/jdk -e JAVA_OPTS="$(echo $JVM_FLAGS)" \
  --entrypoint bash "$IMAGE" -c '
    export PATH=/usr/share/logstash/vendor/jruby/bin:$JAVA_HOME/bin:$PATH
    cp -r /plugin /tmp/plugin && cd /tmp/plugin && rm -rf verify Gemfile.lock .bundle
    jruby -v && jruby -S bundle install \
      && jruby -S bundle exec rspec --format documentation \
      && if [ -n "$IPINFO_TOKEN" ]; then
           jruby -S bundle exec rspec --tag integration --format documentation
         else
           echo "Skipping integration specs: IPINFO_TOKEN is not set"
         fi' \
  >"$OUT/5-rspec.log" 2>&1
[ $? -eq 0 ] && record PASS "rspec (see out/5-rspec.log)" || record FAIL "rspec (see out/5-rspec.log)"
[ -z "$IPINFO_TOKEN" ] && record SKIP "integration spec (IPINFO_TOKEN not set)"

echo
echo "### Summary"
printf '%s\n' "${results[@]}"
echo "Logs: $OUT"
echo "Cleanup: docker volume rm $VOLUME; docker image rm $IMAGE"
printf '%s\n' "${results[@]}" | grep -q '^FAIL' && exit 1 || exit 0
