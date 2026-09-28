# How to get a change in

## Branches and pull requests

- Branch from `main`: `<area>/<short-thing>` — `net/wireguard-generator`, `app/cell-chart`, `obs/vector-config`.
- Commit messages: `<area>: <what changed>` — `plt: add chrony to common role`. Present tense, no full stop.
- Open a pull request. One reviewer approves. The reviewer is another lead, not your own assistant.
- `main` must always be safe to apply. If it is broken, fixing it comes before anything else.

## Pull request checklist

- [ ] It runs on my dev VM (say what you ran)
- [ ] Running it twice changes nothing the second time
- [ ] No secrets, keys, tokens, passwords or real participant data
- [ ] Paths, addresses and names come from variables or a contract file, not typed in
- [ ] A runbook entry exists or is updated
- [ ] If a contract changed: the pull request is labelled `contract` and announced at stand-up

## Reviewing

Reviewing is not optional politeness — it is how nine areas stay one platform. Read for: does it match the contract, will it run twice, can someone else operate it at 2am, does it leak anything.

## What never goes in the repository

Private keys, `.env` files with real values, WireGuard configurations, participant personal data, identity documents, database dumps, screenshots with credentials in them.
