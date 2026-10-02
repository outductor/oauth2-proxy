---
id: discord
title: Discord
---

1. Create an application in the [Discord Developer Portal](https://discord.com/developers/applications).
2. In the application's OAuth2 settings, add the redirect `https://<oauth2-proxy>/oauth2/callback`, substituting
   `<oauth2-proxy>` with the actual hostname that oauth2-proxy is running on.
3. Note the Client ID and Client Secret.

Guild (server) and role restrictions can only be set in the [alpha configuration](../alpha_config.md), so the Discord
provider should be configured there:

```yaml
providers:
  - id: discord
    provider: discord
    clientID: <Client ID>
    clientSecret: <Client Secret>
    discordConfig:
      guilds:
        # Any member of this guild may log in
        - id: "111111111111111111"
        # Members of this guild may log in only with one of these roles
        - id: "222222222222222222"
          roles:
            - "333333333333333333"
```

A user may log in when they meet the restriction of any configured guild. Guild and role IDs can be copied in the
Discord client after enabling Developer Mode under User Settings -> Advanced.

The default scope is `identify guilds`. When any guild has role restrictions, `guilds.members.read` is added
automatically to read the user's roles.

:::warning
Without any configured guilds, every Discord account can log in, and a warning is logged at startup. The legacy
`--provider=discord` flags cannot configure guilds.
:::

### User information

Discord does not provide an email address with the default scopes. The session stores the user's Discord user ID as
both the user and the email, so `X-Forwarded-User` and `X-Forwarded-Email` contain the numeric user ID. The display
name (or username if no display name is set) is used as the preferred username.

Because the email is a user ID, it never matches an email domain. Either set `--email-domain=*`, or leave it unset and
list the allowed Discord user IDs, one per line, in `--authenticated-emails-file`.

### Groups

The session groups contain:

- the ID of each configured guild the user is a member of
- `<guild ID>:<role ID>` for each role the user has in configured guilds that have role restrictions

Guilds that are not configured are never added to the groups. These groups can be used with `allowedGroups` or
passed to upstreams with `--pass-user-headers` / `--set-xauthrequest`.

### Revoking access

Guild and role membership is checked at login. To also remove access when a user leaves a guild or loses a role, set
`--cookie-refresh` (for example `--cookie-refresh=1h`). On every refresh the access token is refreshed, the membership
is re-read and sessions that no longer meet the restrictions are rejected. The session expires when the Discord access
token does (`expires_in`, currently 7 days), so the refresh period should be shorter than that.
