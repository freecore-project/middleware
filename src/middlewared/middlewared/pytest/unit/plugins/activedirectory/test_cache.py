from types import SimpleNamespace

from middlewared.plugins.activedirectory_.cache import augment_gencache_keys


RID_DOMAIN = [{
    'low_id': 100000001,
    'high_id': 200000000,
    'id_type_both': True,
}]


def test_nss_enumeration_supplies_domain_ids_missing_from_gencache():
    keys = augment_gencache_keys(
        [
            b'IDMAP/GID2SID/90000003\x00',
            b'IDMAP/UID2SID/65534\x00',
        ],
        [SimpleNamespace(pw_uid=100038603)],
        [SimpleNamespace(gr_gid=100000513)],
        RID_DOMAIN,
    )

    assert keys == [
        b'IDMAP/GID2SID/90000003\x00',
        b'IDMAP/UID2SID/65534\x00',
        b'IDMAP/UID2SID/100038603\x00',
        b'IDMAP/GID2SID/100038603\x00',
        b'IDMAP/GID2SID/100000513\x00',
        b'IDMAP/UID2SID/100000513\x00',
    ]


def test_non_both_backend_keeps_passwd_and_group_ids_separate():
    keys = augment_gencache_keys(
        [],
        [SimpleNamespace(pw_uid=100038603)],
        [SimpleNamespace(gr_gid=100000513)],
        [{
            'low_id': 100000001,
            'high_id': 200000000,
            'id_type_both': False,
        }],
    )

    assert keys == [
        b'IDMAP/UID2SID/100038603\x00',
        b'IDMAP/GID2SID/100000513\x00',
    ]


def test_legacy_gencache_entries_remain_unchanged_without_nss_enumeration():
    keys = augment_gencache_keys(
        [
            b'IDMAP/UID2SID/100038603\x00',
            b'IDMAP/GID2SID/100000513\x00',
        ],
        [],
        [],
        RID_DOMAIN,
    )

    assert keys == [
        b'IDMAP/UID2SID/100038603\x00',
        b'IDMAP/GID2SID/100000513\x00',
    ]


def test_out_of_range_nss_entries_do_not_change_existing_gencache_keys():
    keys = augment_gencache_keys(
        [
            b'IDMAP/UID2SID/not-an-id\x00',
            b'IDMAP/GID2SID/200000000\x00',
            b'SID2NAME/S-1-5-21\x00',
        ],
        [SimpleNamespace(pw_uid=200000000)],
        [SimpleNamespace(gr_gid=65534)],
        RID_DOMAIN,
    )

    assert keys == [
        b'IDMAP/UID2SID/not-an-id\x00',
        b'IDMAP/GID2SID/200000000\x00',
        b'SID2NAME/S-1-5-21\x00',
    ]
