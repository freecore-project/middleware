# API documentation assets

These files are shipped with middlewared and served by Flask under the
NAS's `/api/docs/static/` route. The API index and WebSocket reference use
Bootstrap 3.4.1 and its compatible jQuery 3.7.1 dependency. The existing
Swagger UI distribution remains supplied by the `freenas/swagger-ui` port.
The REST reference uses system font fallbacks and disables the external
Swagger validator.

`manifest.json` records each pinned npm release archive, its SHA-256, and
the SHA-256 of each copied file. Distribution files are unmodified. Keep
the Bootstrap and jQuery license files and Bootstrap's local font assets
when updating the dependencies. An upgrade must preserve the existing tab
and WebSocket navigation and work with all external requests blocked.

Upstream projects:

- https://github.com/twbs/bootstrap/tree/v3.4.1 (MIT)
- https://github.com/jquery/jquery/tree/3.7.1 (MIT)
