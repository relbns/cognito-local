#!/usr/bin/env python3
"""Smoke test of cognito-local through boto3. Usage: boto3_smoke.py [endpoint], default http://localhost:9229."""
import os
import sys
import uuid

import boto3

endpoint = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:9229"
os.environ["AWS_ENDPOINT_URL_COGNITO_IDENTITY_PROVIDER"] = endpoint
os.environ.setdefault("AWS_ACCESS_KEY_ID", "local")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "local")

cognito = boto3.client("cognito-idp", region_name="us-east-1")
failures = []


def check(label, condition):
    print(("ok   " if condition else "FAIL ") + label)
    if not condition:
        failures.append(label)


def expect_error(label, exception_type, call):
    try:
        call()
    except exception_type as error:
        status = error.response["ResponseMetadata"]["HTTPStatusCode"]
        check(f"{label} -> {error.response['Error']['Code']} ({status})", status == 400)
        return
    except Exception as error:  # noqa: BLE001
        check(f"{label} raised {type(error).__name__}: {error}", False)
        return
    check(f"{label} raised nothing", False)


pool_id = cognito.create_user_pool(
    PoolName=f"boto3-{uuid.uuid4().hex[:6]}", UsernameAttributes=[], AutoVerifiedAttributes=["email"]
)["UserPool"]["Id"]
client_id = cognito.create_user_pool_client(
    UserPoolId=pool_id,
    ClientName="web",
    ExplicitAuthFlows=["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
)["UserPoolClient"]["ClientId"]
check("endpoint taken from AWS_ENDPOINT_URL_COGNITO_IDENTITY_PROVIDER", cognito.meta.endpoint_url.rstrip("/") == endpoint.rstrip("/"))

sign_up = cognito.sign_up(
    ClientId=client_id,
    Username="jane",
    Password="Passw0rd!",
    UserAttributes=[{"Name": "email", "Value": "jane@example.test"}],
)
check("SignUp returns UserSub, unconfirmed", bool(sign_up["UserSub"]) and sign_up["UserConfirmed"] is False)
cognito.admin_confirm_sign_up(UserPoolId=pool_id, Username="jane")

auth = cognito.initiate_auth(
    ClientId=client_id,
    AuthFlow="USER_PASSWORD_AUTH",
    AuthParameters={"USERNAME": "jane", "PASSWORD": "Passw0rd!"},
)["AuthenticationResult"]
check("InitiateAuth USER_PASSWORD_AUTH returns tokens", bool(auth["AccessToken"]) and bool(auth["RefreshToken"]))

me = cognito.get_user(AccessToken=auth["AccessToken"])
check("GetUser with the access token", me["Username"] == "jane")

cognito.create_group(UserPoolId=pool_id, GroupName="editors")
cognito.admin_add_user_to_group(UserPoolId=pool_id, Username="jane", GroupName="editors")
groups = cognito.admin_list_groups_for_user(UserPoolId=pool_id, Username="jane")["Groups"]
check("AdminAddUserToGroup / AdminListGroupsForUser", [g["GroupName"] for g in groups] == ["editors"])

user = cognito.admin_get_user(UserPoolId=pool_id, Username="jane")
check("AdminGetUser parses UserCreateDate as datetime", hasattr(user["UserCreateDate"], "year"))

users = cognito.list_users(UserPoolId=pool_id, Filter='email = "jane@example.test"')["Users"]
check("ListUsers with a filter", [u["Username"] for u in users] == ["jane"])

expect_error(
    "SignUp with a taken username",
    cognito.exceptions.UsernameExistsException,
    lambda: cognito.sign_up(ClientId=client_id, Username="jane", Password="Passw0rd!"),
)
expect_error(
    "InitiateAuth with a wrong password",
    cognito.exceptions.NotAuthorizedException,
    lambda: cognito.initiate_auth(
        ClientId=client_id,
        AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": "jane", "PASSWORD": "Wr0ng-password"},
    ),
)
expect_error(
    "SignUp with a weak password",
    cognito.exceptions.InvalidPasswordException,
    lambda: cognito.sign_up(ClientId=client_id, Username="weak", Password="short"),
)
expect_error(
    "AdminGetUser for a missing user",
    cognito.exceptions.UserNotFoundException,
    lambda: cognito.admin_get_user(UserPoolId=pool_id, Username="nobody"),
)

cognito.delete_user_pool(UserPoolId=pool_id)
print(f"\nboto3 {boto3.__version__}: {'all checks passed' if not failures else f'{len(failures)} failed'}")
sys.exit(1 if failures else 0)
