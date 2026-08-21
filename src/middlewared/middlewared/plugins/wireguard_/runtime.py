import subprocess
import time


RECENT_HANDSHAKE_SECONDS = 180


def read_peer_runtime(interface):
    """Read only non-secret wg fields; never use dump, which includes private keys."""
    values = {}
    try:
        for field, width in (('latest-handshakes', 2), ('endpoints', 2), ('transfer', 3)):
            result = subprocess.run(
                ['wg', 'show', interface, field], capture_output=True, text=True, timeout=3,
            )
            if result.returncode:
                return None
            rows = {}
            for line in result.stdout.splitlines():
                parts = line.split('\t')
                if len(parts) != width:
                    return None
                rows[parts[0]] = parts[1:]
            values[field] = rows

        snapshot = {}
        now = int(time.time())
        for key in values['latest-handshakes'].keys() & values['endpoints'].keys() & values['transfer'].keys():
            handshake = int(values['latest-handshakes'][key][0])
            received, sent = map(int, values['transfer'][key])
            if min(handshake, received, sent) < 0:
                return None
            age = max(0, now - handshake) if handshake else None
            endpoint = values['endpoints'][key][0]
            snapshot[key] = {
                'latest_handshake': handshake or None,
                'handshake_age': age,
                'endpoint': None if endpoint == '(none)' else endpoint,
                'rx_bytes': received,
                'tx_bytes': sent,
                'state': ('NEVER_CONNECTED' if age is None else
                          'RECENT' if age <= RECENT_HANDSHAKE_SECONDS else 'STALE'),
            }
        return snapshot
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return None


def peer_status_rows(peers, snapshot):
    """Keep the status response independent of credential-bearing CRUD records."""
    result = []
    for peer in peers:
        row = {key: peer[key] for key in ('id', 'name', 'public_key', 'allowed_ips', 'keepalive', 'enabled')}
        state = 'DISABLED' if not peer['enabled'] else 'UNAVAILABLE' if snapshot is None else 'NOT_LOADED'
        runtime = None if not peer['enabled'] or snapshot is None else snapshot.get(peer['public_key'])
        row['runtime'] = runtime or {
            'latest_handshake': None, 'handshake_age': None, 'endpoint': None,
            'rx_bytes': None, 'tx_bytes': None, 'state': state,
        }
        result.append(row)
    return result
