# umask

**Elevated permissions for Discord staff. Only when needed.**

umask is a Discord security bot that gives authorised staff temporary access to an elevated role after authentication. When a session ends, umask removes that role, reducing the time powerful permissions remain assigned to staff accounts.

**[Website & installation](https://umask.app)** · **[Support](mailto:support@umask.app)**

## How it works

1. **Choose your roles.** The server owner runs `/setup` to select a permanent staff role, an elevated-permissions role and allowed session lengths.
2. **Issue a private code.** The owner runs `/issue` for a staff member, who collects their authentication phrase using `/receive`.
3. **Authenticate when needed.** Staff use `/authenticate` to receive the elevated role temporarily. They can end their session early with `/signout`, and the owner can invalidate a code with `/revoke`.

Setup and authentication happen entirely within Discord. Server owners can also use `/status` to review credentials and sessions.

## What permissions does umask need?

- **Manage Roles**, so it can assign and remove your chosen elevated role.
- **A higher role position** than that elevated role. Place the umask bot role directly above it in Discord's role list.

umask does **not** require Administrator, access to message content, or the permissions contained in the elevated role. You configure those permissions yourself; umask does not modify them.

## A safeguard, not a guarantee

umask is intended to reduce the risk posed by compromised staff accounts by limiting how long elevated permissions are available. It **cannot guarantee** that a server is immune to compromise or misuse. It cannot prevent actions taken during an active elevated session, and outages may delay role removal.

## Install, support and policies

Visit **[umask.app](https://umask.app)** to install the bot and find setup information. For help, use `/support` in Discord or email **[support@umask.app](mailto:support@umask.app)**.

[Privacy Policy](https://umask.app/privacy.html) · [Terms of Service](https://umask.app/terms.html) · [Data requests](https://umask.app/data-request.html)
