# FreeCORE template provenance

Source: https://github.com/BastilleBSD/templates

Revision: `4659727b86ec2972c1040e57a7fe4a32dfb98b70`

Upstream directory: `www/nginx`

This is a bundled, pinned subset for explicit administrative import and application. The repository license is retained in LICENSE. Installed packages are fetched from the jail package repository and are not pinned by this source revision. Runtime compatibility must be verified on the target FreeCORE image.

The bundled nginx.conf is unchanged. The active Bastillefile omits the upstream CP instruction: the FreeCORE API stages the fixed configuration inside the jail before applying the recipe, without host-side copying into jail-controlled paths. The upstream test helper is omitted. Applying the template installs nginx, replaces its configuration with the bundled configuration, enables the service and restarts it.
