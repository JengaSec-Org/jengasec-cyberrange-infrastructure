"""Reviewable hook for the provisioning worker's nft rule generator.

This module only renders companion observation rules. The caller retains every
original verdict rule. It does not invoke nft or mutate a running ruleset.
"""

import re


def classify(rule):
    if " ct state invalid " in rule:
        return "invalid"
    if 'comment "JengaSec peer isolation"' in rule:
        return "peer_isolation"
    if 'comment "JengaSec protected destinations"' in rule:
        return "protected_destination"
    if 'comment "JengaSec no inbound initiation"' in rule:
        return "inbound_unsolicited"
    if " ct state established,related accept" in rule:
        return "established_return"
    if 'comment "JengaSec default deny"' in rule:
        return "default_deny"
    if re.search(r'comment "JengaSec (allow|deny) participant [0-9]+ target [0-9]+"$', rule):
        return "assigned_policy"
    raise ValueError("unknown provisioning rule; review observation mapping")


def add_verdict_observation(lines, table, chain="forward_guard", rate=2, burst=10):
    """Preserve verdict behavior when the log rate limit is exhausted.

    A rate limit in a verdict rule could skip that verdict. Each log-only rule
    therefore precedes its unchanged verdict rule and has identical selectors.
    No participant or target identifier appears in the fixed log prefix.
    """
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", table) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", chain):
        raise ValueError("invalid nft table or chain")
    if type(rate) is not int or type(burst) is not int or not 1 <= rate <= 10 or not rate <= burst <= 50:
        raise ValueError("invalid observation rate")
    prefix = f"add rule inet {table} {chain} "
    flush = f"flush chain inet {table} {chain}"
    output = []
    for line in lines:
        if line == flush:
            output.append(line)
            continue
        if not line.startswith(prefix) or "\n" in line or "JENGASEC_OBS:" in line:
            raise ValueError("unexpected generator command")
        match = re.fullmatch(r"(.*) (accept|drop)(?: comment \"[^\"\n]*\")?", line)
        if match is None:
            raise ValueError("generator rule has no supported terminal verdict")
        reason = classify(line)
        verdict = "allowed" if match.group(2) == "accept" else "refused"
        output.append(match.group(1) + f' limit rate {rate}/second burst {burst} packets log prefix "JENGASEC_OBS:{verdict}:{reason} " level info')
        output.append(line)
    if not output or output[0] != flush:
        raise ValueError("generator must start with its scoped chain flush")
    return output
