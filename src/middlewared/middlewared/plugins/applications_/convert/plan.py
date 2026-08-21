"""The plan document (the internal development record).

A plan is data: typed entries (``carry`` / ``rewrite`` / ``drop`` / ``refuse`` /
``hop``), each with its own human-readable string, plus the available modes and
the recommendation.  The CLI prints it, the wizard renders it; neither owns the
wording.  Its id is the hash of its canonical form, so "the operator confirmed
this plan" names one exact document.
"""
import hashlib
import json
import re

ENTRY_TYPES = ('carry', 'rewrite', 'drop', 'refuse', 'hop', 'note')


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')


def plan_id(plan):
    body = {key: value for key, value in plan.items() if key != 'plan_id'}
    return hashlib.sha256(canonical(body)).hexdigest()


def entry(kind, human, **fields):
    if kind not in ENTRY_TYPES:
        raise ValueError(f'unknown plan entry type {kind!r}')
    result = {'type': kind, 'human': human}
    result.update(fields)
    return result


def version_key(version):
    """A comparable key for package-style versions: 8.5.27, 13.1.1_2, v10.4.19."""
    if not isinstance(version, str):
        return None
    text = version.strip().lstrip('v')
    text = text.split('_', 1)[0].split(',', 1)[0]
    parts = re.findall(r'\d+', text)
    return tuple(int(part) for part in parts) if parts else None


def not_older(target, source):
    """True when the target version is at least the source version, or either is unknown.

    Compared to the depth both sides state: a FreeBSD package's fourth component is
    a build number (``4.0.15.2941``) and the image's ``4.0.15`` is the same release,
    not an older one.
    """
    target_key = version_key(target)
    source_key = version_key(source)
    if target_key is None or source_key is None:
        return True
    length = min(len(target_key), len(source_key))
    return target_key[:length] >= source_key[:length]
