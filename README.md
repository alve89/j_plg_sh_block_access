# Block Access

System plugin to restrict access to the Joomla frontend, administrator area, or both until a configured security key is supplied as a GET/POST parameter name.

## Compatibility

- Joomla 4.2 - 6.x
- PHP 7.2.5+

The plugin uses a namespaced extension class, a DI service provider and `SubscriberInterface` event listeners. The runtime plugin code does not depend on Joomla's backward-compatibility plugin on Joomla 5 or 6.

## Setup

1. Install and enable **System - Block Access**.
2. Configure the main security key.
3. Optionally configure a separate frontend security key.
4. Select **Site**, **Administrator** or **All**.
5. Select either a **401 message** or a **redirect**.

To unlock an area, append the configured key as a query parameter name, for example:

`https://example.org/?MySecretKey`

The successful unlock is stored in the current Joomla session. Changing the configured key automatically invalidates any previously unlocked sessions.

## Redirect behaviour

The redirect target may be an absolute `http(s)` URL or a path relative to the Joomla root, such as `/maintenance/`.

If the redirect target itself is a Joomla page, that exact target is intentionally allowed in redirect mode to prevent a redirect loop. This exception applies only to redirect mode; 401 message mode remains blocked everywhere.

## Hardening options

These live under the plugin's `Hardening` tab:

- **Also block the Web Services API** (default: no) - Joomla's REST API (`/api`) can authenticate independently of the frontend/backend login forms (e.g. via HTTP Basic Auth) and is therefore *not* covered by the site/administrator protection above unless enabled here. Enabling this blocks the entire API for anyone without the security key or an allow-listed IP. Only enable this if you don't rely on the API for anything else.
- **Always-allowed IP addresses** (default: empty) - one IP address or CIDR range per line (e.g. `203.0.113.4` or `198.51.100.0/24`) that bypasses this plugin entirely, for all protected areas. Useful for an office or VPN address.

## Notes

- CLI is not affected by this plugin.
- Site and administrator each have their own Joomla session, so unlocking one does not unlock the other, even under **All**.
- An administrator logging out is redirected to the frontend only when the administrator area is actually protected (`area` is `Administrator` or `All` and a key is configured) - otherwise the normal Joomla logout flow is left untouched.
