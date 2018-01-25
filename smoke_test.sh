#!/usr/bin/env bash

TESTING_TAG=${1:-latest}

mkdir smoke

cat << EOF > smoke/rules.yml
rules:
- source: /simple
  target: http://test.sample/check-simple
- source: /regex/(.+)
  target: http://test.regex/\1
  regex:  true

admin:
  path: /admin
  username: smoke
  password: testing
EOF

docker run -d -p 5000:17123                     \
  -e HTTP_HOST=0.0.0.0 -e HTTP_PORT=17123       \
  -v $PWD/smoke:/smoke:ro -e RULES_DIR=/smoke   \
  redirect-server:$TESTING_TAG  > /dev/null

for _ in $(seq 10); do
  curl -fs http://localhost:5000/metrics > /dev/null
  if [ "$?" == "0" ]; then
    break
  else
    sleep 1
  fi
done

echo -n "Check /simple : "
curl -fsv http://localhost:5000/simple 2>&1 | grep '< Location: http://test.sample/check-simple' || exit 1

echo -n "Check /regex/first : "
curl -fsv http://localhost:5000/regex/first 2>&1 | grep '< Location: http://test.regex/first' || exit 1

echo -n "Check /regex/second : "
curl -fsv http://localhost:5000/regex/second 2>&1 | grep '< Location: http://test.regex/second' || exit 1

echo -n "Check /admin : "
curl -fsv -u 'smoke:testing' http://localhost:5000/admin 2>&1 | grep '< HTTP/1.0 200 OK' || exit 1

echo "Successfully finished"
