def augment_gencache_keys(gencache_keys, passwd_entries, group_entries, known_domains):
    """
    Add NSS-enumerated directory-service IDs to Samba's gencache keys.

    Samba 4.24 may enumerate passwd and group records without populating domain
    UID2SID/GID2SID gencache entries. Keep consuming those entries when present,
    but also use the NSS records that fill_cache already enumerates. RID and
    AUTORID IDs are valid as both UID and GID values.
    """
    keys = list(gencache_keys)
    seen = set(keys)

    def add_nss_id(xid, prefix, other_prefix):
        domain = next((
            domain for domain in known_domains
            if domain['low_id'] <= xid < domain['high_id']
        ), None)
        if not domain:
            return

        prefixes = [prefix]
        if domain['id_type_both']:
            prefixes.append(other_prefix)

        for id_prefix in prefixes:
            key = f'{id_prefix}/{xid}\x00'.encode()
            if key not in seen:
                seen.add(key)
                keys.append(key)

    for entry in passwd_entries:
        add_nss_id(entry.pw_uid, 'IDMAP/UID2SID', 'IDMAP/GID2SID')

    for entry in group_entries:
        add_nss_id(entry.gr_gid, 'IDMAP/GID2SID', 'IDMAP/UID2SID')

    return keys
