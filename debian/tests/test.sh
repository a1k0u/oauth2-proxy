#!/bin/bash

set -e

echo "open value" > $PWD/open
echo "secure value" > $PWD/secure

openssl genrsa -out $PWD/private.pem 2048 >/dev/null 2>&1
openssl rsa -in $PWD/private.pem -pubout -out $PWD/public.pem >/dev/null 2>&1

HEADER='{"alg": "RS256", "typ": "JWT"}'
BODY="{\"iss\": \"http://127.0.0.1:5556\", \"aud\": \"oauth2-proxy\", \"exp\": $(echo "$(date +%s) + 3600" | bc)}"

encode_base64() {
    echo -n "$1" | base64 -w 0 | sed s/\+/-/ | sed -E s/=+$//
}
PAYLOAD="$(encode_base64 "$HEADER").$(encode_base64 "$BODY")"

SIGNATURE=$(echo -n "$PAYLOAD" | openssl dgst -sha256 -binary -sign $PWD/private.pem  | openssl enc -base64 | tr -d '\n=' | tr -- '+/' '-_')
JWT="$PAYLOAD.$SIGNATURE"

oauth2-proxy \
    --provider oidc \
    --client-id oauth2-proxy \
    --client-secret proxy \
    --redirect-url http://127.0.0.1:4180/oauth2/callback \
    --oidc-issuer-url http://127.0.0.1:5556 \
    --cookie-secret=0123456789012345 \
    --email-domain='*' \
    --skip-jwt-bearer-tokens=true \
    --bearer-token-login-fallback=false \
    --upstream file://$PWD/#/ \
    --skip-oidc-discovery \
    --login-url http://127.0.0.1:5556/authorize \
    --redeem-url http://127.0.0.1:5556/token \
    --oidc-public-key-file $PWD/public.pem \
    --skip-auth-route GET=/open 2>&1 &

PID=$!
trap "kill -15 $PID" EXIT

while ! curl -m 5 -s 127.0.0.1:4180/ready > /dev/null 2>&1; do
    echo "Waiting for oauth2-proxy to be ready..."
    sleep 1
done

TEST_OPEN_EXPECTED=$(printf "open value\n200" | md5sum)
TEST_OPEN_ACTUAL=$(curl -m 5 -s 127.0.0.1:4180/open -w '%{response_code}' | md5sum)
if [ "$TEST_OPEN_EXPECTED" != "$TEST_OPEN_ACTUAL" ]; then
    echo "Test open failed" >&2
    exit 1
else
    echo "Test open passed"
fi

TEST_SECURE_WITH_JWT_EXPECTED=$(printf "secure value\n200" | md5sum)
TEST_SECURE_WITH_JWT_ACTUAL=$(curl -m 5 -s 127.0.0.1:4180/secure -H "Authorization: Bearer $JWT" -w '%{response_code}' | md5sum)
if [ "$TEST_SECURE_WITH_JWT_EXPECTED" != "$TEST_SECURE_WITH_JWT_ACTUAL" ]; then
    echo "Test secure failed" >&2
    exit 1
else
    echo "Test secure passed"
fi

TEST_SECURE_INVALID_JWT_EXPECTED=$(printf "Forbidden\n403" | md5sum)
TEST_SECURE_INVALID_JWT_ACTUAL=$(curl -m 5 -s 127.0.0.1:4180/secure -H "Authorization: Bearer invalid" -w '%{response_code}' | md5sum)
if [ "$TEST_SECURE_INVALID_JWT_EXPECTED" != "$TEST_SECURE_INVALID_JWT_ACTUAL" ]; then
    echo "Test secure invalid JWT failed" >&2
    exit 1
else
    echo "Test secure invalid JWT passed"
fi
