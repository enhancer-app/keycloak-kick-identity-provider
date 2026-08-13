# Manual End-to-End Test

Run this test using a non-production Keycloak realm and a dedicated Kick developer application.
Do not commit its client ID, client secret, authorization codes, access tokens, refresh tokens,
or user data.

## 1. Build and start Keycloak

```bash
./gradlew clean build
docker build -t keycloak-kick:local .
docker run --rm -p 8080:8080 \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin \
  -e KC_BOOTSTRAP_ADMIN_PASSWORD='<choose-a-local-password>' \
  keycloak-kick:local start-dev
```

Open `http://localhost:8080/admin/`, sign in, and create a test realm.

## 2. Register the callback with Kick

In the Kick developer portal, create or open a test OAuth application. Register this exact
redirect URI, replacing placeholders with your Keycloak public base URL, realm and alias:

```text
https://<keycloak-host>/realms/<realm>/broker/<provider-alias>/endpoint
```

For the default alias `kick` in a local realm named `demo`, this is:

```text
http://localhost:8080/realms/demo/broker/kick/endpoint
```

Use HTTPS for any non-local environment. The URI must match byte-for-byte during the authorization
and token exchange; a different scheme, host, port, path, trailing slash, realm, or alias fails.

## 3. Configure the provider

1. In the target realm open **Identity providers**.
2. Choose **Kick** from the social provider list.
3. Leave alias as `kick`, or use a short stable alias and update the Kick redirect URI to match.
4. Enter the Kick **Client ID** and **Client Secret**.
5. Leave **Default Scopes** as `user:read` unless your Kick application needs additional scopes.
6. Select **Import** sync mode for one-time import or **Force** to refresh provider-managed
   profile values at every login.
7. Leave **Store Tokens** off unless a downstream Keycloak integration specifically needs the
   upstream token. It is off by default.
8. Leave **Import e-mail** off unless your realm policy accepts Kick e-mail as optional profile
   data. It never identifies the account.
9. Leave **Store profile picture** on unless user attributes should not contain remote avatar URLs.
10. Save.

The authorization, token, and profile endpoint fields are intentionally not configurable. The
provider uses Kick’s fixed production endpoints and always enables PKCE `S256`.

## 4. Verify a first login

1. Open an application login URL for the test realm.
2. Choose **Kick**.
3. Verify the redirect URL starts with `https://id.kick.com/oauth/authorize` and includes
   `response_type=code`, `code_challenge`, and `code_challenge_method=S256`.
4. Authenticate and consent at Kick.
5. Confirm Keycloak returns to the application and creates or links the user through the standard
   first-login flow.
6. In Keycloak, inspect **Users** and **Identity provider links**. The provider link user ID must
   equal Kick `data[0].user_id`; do not expect it to be an e-mail, display name, channel slug or
   avatar URL.
7. If avatar storage is enabled, inspect the configured user attribute (default
   `kick_profile_picture`).

## 5. Verify synchronization

1. Change the Kick display name or profile picture on the test account, if the platform permits.
2. Log in again with **Import** mode. Existing Keycloak profile data should not be forcibly
   replaced by provider data.
3. Select **Force** mode and repeat. Provider-managed fields, including the configured avatar
   attribute and the brokered username, may be refreshed. The federated identity link remains the
   same because it uses the stable Kick `user_id`.

## 6. Negative checks

- Remove or alter the registered callback URI in the Kick developer application. Kick should deny
  the authorization/token flow; Keycloak must show a generic actionable failure without tokens or
  secrets.
- Use an invalid client secret. Verify logs and error pages do not reveal the secret or full
  remote response.
- Disable **Store Tokens**, sign in, and verify that no upstream token is stored in the federated
  identity record.

## Cleanup

Delete the test realm and revoke/delete the test Kick application or its credentials when finished.
