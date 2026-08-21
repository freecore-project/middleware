"""the internal development record: user-defined container labels.

The reserved-prefix rule is the load-bearing one: `io.freecore.*` labels are how query(),
boot recovery and transaction rollback recognise FreeCORE's own containers, so a user label
must never be able to claim one.
"""
import pytest

from middlewared.plugins.applications_.catalog import CatalogContractError, _normalize_labels
from middlewared.plugins.applications_.utils import (
    APPLICATION_LABEL,
    MANAGED_LABEL,
    podman_create_args,
    public_record,
)


def record(**overrides):
    base = {
        'name': 'demo',
        'container_name': 'freecore-app-demo',
        'image': 'registry.example/demo:1',
        'restart_policy': 'always',
        'annotations': [],
        'environment': [],
        'ports': [],
        'volumes': [],
        'labels': [],
    }
    base.update(overrides)
    return base


# -- the container command line ------------------------------------------------------------

def test_user_labels_reach_the_container_beside_freecores_own():
    args = podman_create_args(record(labels=[
        {'name': 'traefik.enable', 'value': 'true'},
        {'name': 'com.example/role', 'value': 'edge'},
    ]))

    pairs = [args[index + 1] for index, value in enumerate(args) if value == '--label']
    assert f'{MANAGED_LABEL}=true' in pairs
    assert f'{APPLICATION_LABEL}=demo' in pairs
    # name-sorted, so the command line is deterministic
    assert pairs[-2:] == ['com.example/role=edge', 'traefik.enable=true']


def test_a_record_without_labels_is_still_buildable():
    args = podman_create_args(record())
    pairs = [args[index + 1] for index, value in enumerate(args) if value == '--label']
    assert pairs == [f'{MANAGED_LABEL}=true', f'{APPLICATION_LABEL}=demo']


def test_query_presents_labels_even_for_a_record_written_before_them():
    older = record()
    older.pop('labels')
    assert public_record(older)['labels'] == []


# -- the catalog Compose contract ----------------------------------------------------------

def test_compose_labels_are_accepted_as_a_mapping_and_sorted():
    assert _normalize_labels({'labels': {'b.key': 'two', 'a.key': 'one'}}) == [
        {'name': 'a.key', 'value': 'one'},
        {'name': 'b.key', 'value': 'two'},
    ]


def test_compose_labels_are_accepted_as_a_name_value_list():
    assert _normalize_labels({'labels': ['a.key=one', 'b.key=two']}) == [
        {'name': 'a.key', 'value': 'one'},
        {'name': 'b.key', 'value': 'two'},
    ]


def test_compose_scalar_label_values_become_strings():
    assert _normalize_labels({'labels': {'a': 1, 'b': True}}) == [
        {'name': 'a', 'value': '1'},
        {'name': 'b', 'value': 'true'},
    ]


def test_a_service_without_labels_declares_none():
    assert _normalize_labels({}) == []


@pytest.mark.parametrize('labels,message', [
    ({'io.freecore.managed': 'false'}, 'reserved'),
    ({'io.freecore.application': 'other'}, 'reserved'),
    ({'-leading-dash': 'x'}, 'valid and unique'),
    ({'spaces are invalid': 'x'}, 'valid and unique'),
    (['no-equals-sign'], 'NAME=value'),
    ('a string', 'list or mapping'),
    ({'a': ['not', 'scalar']}, 'scalar value'),
    ({'a': 'has\nnewline'}, 'invalid value'),
])
def test_a_catalog_service_cannot_declare_an_invalid_or_reserved_label(labels, message):
    with pytest.raises(CatalogContractError, match=message):
        _normalize_labels({'labels': labels})


def test_duplicate_names_are_refused():
    with pytest.raises(CatalogContractError, match='valid and unique'):
        _normalize_labels({'labels': ['a=one', 'a=two']})


def test_too_many_labels_are_refused():
    with pytest.raises(CatalogContractError, match='too many'):
        _normalize_labels({'labels': {f'key{index}': 'x' for index in range(129)}})


def test_an_oversized_value_is_refused():
    with pytest.raises(CatalogContractError, match='invalid value'):
        _normalize_labels({'labels': {'a': 'x' * 4097}})
