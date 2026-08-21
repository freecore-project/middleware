"""The installed API reference must work without CDN resources."""
import hashlib
from html.parser import HTMLParser
import json
from pathlib import Path
import re
from unittest.mock import patch
from urllib.parse import urljoin, urlsplit

import pytest

from middlewared import apidocs


class Resources(HTMLParser):
    def __init__(self, html):
        super().__init__()
        self.urls = []
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag in {'script', 'iframe', 'img'} and attrs.get('src'):
            self.urls.append(attrs['src'])
        if tag == 'link' and attrs.get('rel') == 'stylesheet':
            self.urls.append(attrs['href'])


def get(client, path):
    return client.get(path, headers={'X-Script-Name': '/api/docs'}, follow_redirects=True)


@pytest.mark.parametrize('route', ['/api/docs/', '/api/docs/websocket/'])
def test_reference_assets_resolve_through_the_nas_prefix(route):
    with patch.object(apidocs, 'Client') as client_class:
        client_class.return_value.__enter__.return_value.call.return_value = {}
        with apidocs.app.test_client() as client:
            response = get(client, route)
            assert response.status_code == 200
            resources = Resources(response.get_data(as_text=True)).urls
            assert resources
            for resource in resources:
                url = urlsplit(urljoin('http://nas.example' + route, resource))
                assert url.netloc == 'nas.example'
                assert url.path.startswith('/api/docs/')
                asset = get(client, url.path)
                assert asset.status_code == 200, url.path
                if asset.mimetype == 'text/css':
                    for reference in re.findall(r'url\(["\']?([^"\')]+)', asset.get_data(as_text=True)):
                        font = urlsplit(urljoin(url.geturl(), reference))
                        assert font.netloc == 'nas.example'
                        assert get(client, font.path).status_code == 200, font.path


def test_rest_reference_uses_only_local_swagger_assets_and_no_validator():
    with apidocs.app.test_client() as client:
        response = get(client, '/api/docs/restful/')
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    for resource in Resources(html).urls:
        url = urlsplit(urljoin('http://nas.example/api/docs/restful/', resource))
        assert url.netloc == 'nas.example'
        assert url.path.startswith('/api/docs/restful/static/')
    assert re.search(r'validatorUrl\s*:\s*null\b', html)


def test_vendored_distribution_files_match_their_manifest():
    root = Path(apidocs.__file__).parent / 'static' / 'vendor'
    for dependency in json.loads((root / 'manifest.json').read_text()):
        directory = root / f"{dependency['name']}-{dependency['version']}"
        assert dependency['source'].startswith('https://registry.npmjs.org/')
        assert any(name.startswith('LICENSE') for name in dependency['files'])
        for name, expected in dependency['files'].items():
            assert hashlib.sha256((directory / name).read_bytes()).hexdigest() == expected
