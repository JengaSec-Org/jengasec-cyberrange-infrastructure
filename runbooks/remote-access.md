# Runbook: reaching Server 3 from outside school

**Owner:** NET · Status: fill in once the tunnel is running.

## What this is
Nobody opens ports on the school network. Server 3 dials out to Cloudflare, and named staff reach it through Cloudflare Access with their own SSH key.

## Set up once
1. Generate a key: `ssh-keygen -t ed25519 -C "<code>@jengasec"`.
2. Open a pull request adding the public key to `ansible/group_vars/all/users.yml`.
3. Wait for it to be merged and applied. You will be told which tier you have.

## Connecting
```
# with cloudflared installed:
ssh <you>@<host>   # using the ProxyCommand below in ~/.ssh/config

Host jengasec-*
  ProxyCommand cloudflared access ssh --hostname %h
  User <you>
  IdentityFile ~/.ssh/id_ed25519
```

## When it does not work
| Symptom | Likely cause | Do this |
|---|---|---|
| Access page never loads | Tunnel is down on the edge VM | Tell NET in the incident channel |
| Permission denied | Key not applied yet, or wrong tier | Check your pull request was merged and applied |
| Works for others, not you | Your email is not in the Access policy | Ask NET to add it |

## If you cannot get in at all
Work on your dev VM and open a pull request. That is a normal way to work here, not a fallback.
