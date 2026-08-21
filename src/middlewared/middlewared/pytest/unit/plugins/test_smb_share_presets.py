from middlewared.plugins.smb import (
    SharingSMBService, SMBSharePreset, preserved_creation_params,
)


CREATE_ATTRS = SharingSMBService.do_create.accepts[0].attrs


def creation_payload(**overrides):
    """A sharingsmb_create payload as the schema layer hands it to do_create:
    every defaulted attribute filled, caller overrides applied on top."""
    data = {
        name: attr.default for name, attr in CREATE_ATTRS.items()
        if attr.has_default
    }
    data.update(overrides)
    return data


def apply_preset_then_preserve(data):
    """The do_create ordering under test: preset params clobber, preserved
    explicit values are re-applied. auxsmbconf merge is not modelled — the
    helper must never preserve that key."""
    preserved = preserved_creation_params(
        data, CREATE_ATTRS, SMBSharePreset[data['purpose']].value['params'],
    )
    params = SMBSharePreset[data['purpose']].value['params'].copy()
    params.pop('auxsmbconf', None)
    data.update(params)
    data.update(preserved)
    return data


def test_explicit_timemachine_survives_default_preset():
    data = creation_payload(path='/mnt/tank/tm', name='TIMEMACHINE', timemachine=True)
    assert preserved_creation_params(
        data, CREATE_ATTRS, SMBSharePreset['DEFAULT_SHARE'].value['params'],
    ) == {'timemachine': True}
    assert apply_preset_then_preserve(data)['timemachine'] is True


def test_omitted_fields_remain_preset_controlled():
    data = apply_preset_then_preserve(creation_payload(path='/mnt/tank/plain', name='PLAIN'))
    assert data['timemachine'] is False
    assert data['recyclebin'] is False
    assert data['acl'] is True


def test_preset_authority_intact_without_explicit_divergence():
    data = apply_preset_then_preserve(
        creation_payload(path='/mnt/tank/tm2', name='TM2', purpose='ENHANCED_TIMEMACHINE')
    )
    assert data['timemachine'] is True
    assert data['path_suffix'] == '%U'


def test_explicit_values_survive_enhanced_preset():
    data = apply_preset_then_preserve(
        creation_payload(
            path='/mnt/tank/tm3', name='TM3',
            purpose='ENHANCED_TIMEMACHINE', path_suffix='%M',
        )
    )
    assert data['path_suffix'] == '%M'
    assert data['timemachine'] is True


def test_non_boolean_explicit_values_survive_default_preset():
    data = apply_preset_then_preserve(creation_payload(
        path='/mnt/tank/lan', name='LAN',
        ro=True, recyclebin=True, hostsallow=['192.0.2.0/24'],
    ))
    assert data['ro'] is True
    assert data['recyclebin'] is True
    assert data['hostsallow'] == ['192.0.2.0/24']


def test_auxsmbconf_is_never_preserved():
    data = creation_payload(
        path='/mnt/tank/aux', name='AUX',
        purpose='WORM_DROPBOX', auxsmbconf='worm:grace_period = 900',
    )
    assert 'auxsmbconf' not in preserved_creation_params(
        data, CREATE_ATTRS, SMBSharePreset['WORM_DROPBOX'].value['params'],
    )
