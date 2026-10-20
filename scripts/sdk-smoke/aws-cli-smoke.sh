#!/usr/bin/env bash
# Smoke test of cognito-local through the AWS CLI v2. Usage: aws-cli-smoke.sh [endpoint]
set -euo pipefail

ENDPOINT="${1:-http://localhost:9229}"
export AWS_ACCESS_KEY_ID=local AWS_SECRET_ACCESS_KEY=local AWS_REGION=us-east-1 AWS_PAGER=""
export AWS_CONFIG_FILE=/dev/null AWS_SHARED_CREDENTIALS_FILE=/dev/null
unset AWS_PROFILE AWS_SESSION_TOKEN

aws_idp() { aws cognito-idp --endpoint-url "$ENDPOINT" --output text "$@"; }
ok() { echo "ok   $*"; }
fail() { echo "FAIL $*"; exit 1; }

POOL_ID=$(aws_idp create-user-pool --pool-name "cli-$RANDOM" --username-attributes [] --query UserPool.Id)
CLIENT_ID=$(aws_idp create-user-pool-client --user-pool-id "$POOL_ID" --client-name web \
  --explicit-auth-flows ALLOW_USER_PASSWORD_AUTH ALLOW_REFRESH_TOKEN_AUTH --query UserPoolClient.ClientId)
ok "CreateUserPool $POOL_ID, CreateUserPoolClient $CLIENT_ID"

aws_idp admin-create-user --user-pool-id "$POOL_ID" --username jane --message-action SUPPRESS \
  --user-attributes Name=email,Value=jane@example.test >/dev/null
aws_idp admin-set-user-password --user-pool-id "$POOL_ID" --username jane --password 'Passw0rd!' --permanent
TOKEN=$(aws_idp initiate-auth --client-id "$CLIENT_ID" --auth-flow USER_PASSWORD_AUTH \
  --auth-parameters 'USERNAME=jane,PASSWORD=Passw0rd!' --query AuthenticationResult.AccessToken)
[[ -n "$TOKEN" ]] && ok "InitiateAuth USER_PASSWORD_AUTH" || fail "InitiateAuth returned no token"

[[ "$(aws_idp get-user --access-token "$TOKEN" --query Username)" == jane ]] && ok "GetUser" || fail "GetUser"
[[ "$(aws_idp list-users --user-pool-id "$POOL_ID" --filter 'email = "jane@example.test"' --query 'Users[0].Username')" == jane ]] \
  && ok "ListUsers with a filter" || fail "ListUsers"

if err=$(aws_idp initiate-auth --client-id "$CLIENT_ID" --auth-flow USER_PASSWORD_AUTH \
  --auth-parameters 'USERNAME=jane,PASSWORD=Wr0ng-password' 2>&1); then
  fail "a wrong password signed in"
fi
[[ "$err" == *NotAuthorizedException* ]] && ok "wrong password -> NotAuthorizedException" || fail "unexpected error: $err"

[[ "$(AWS_ENDPOINT_URL_COGNITO_IDENTITY_PROVIDER="$ENDPOINT" aws cognito-idp describe-user-pool \
  --user-pool-id "$POOL_ID" --output text --query UserPool.Id)" == "$POOL_ID" ]] \
  && ok "endpoint from AWS_ENDPOINT_URL_COGNITO_IDENTITY_PROVIDER" || fail "env endpoint"

aws_idp delete-user-pool --user-pool-id "$POOL_ID"
echo
echo "$(aws --version 2>&1 | cut -d' ' -f1): all checks passed"
