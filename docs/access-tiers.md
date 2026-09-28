# Who can reach what

One server, forty-one people. Access is given by tier, not by asking nicely.

| Tier | Reaches | Who | How |
|---|---|---|---|
| 0 | Proxmox host shell and web interface | Platform lead, Security lead, and one named backup | SSH key through Cloudflare Access; no root login, named accounts only |
| 1 | Shell on specific VMs | The area that owns that VM, plus their assistants | SSH key through Cloudflare Access, limited to their VMs |
| 2 | Kubernetes, one namespace | Application Platform, Observability, AI Track | kubeconfig with a namespace-scoped service account |
| 3 | Repository and dev VM only | Everyone else, including most assistants | GitHub; changes reach the server by pull request |

**Rules**

- Keys are `ed25519`, with a passphrase. No shared accounts, ever.
- No password SSH. No root SSH.
- Ask for the lowest tier that lets you do your task. Tiers are removed the day after the event.
- If you cannot reach the server, that is normal: build it on your dev VM and open a pull request.

## Connecting (fill in once the tunnel is up)

```
# one-time
ssh-keygen -t ed25519 -C "<your code>@jengasec"
# add the public key in a pull request to ansible/group_vars/all/users.yml

# connecting
ssh <you>@<host>   # through Cloudflare Access — exact ProxyCommand in runbooks/remote-access.md
```
