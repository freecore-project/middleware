# FreeCORE template provenance

Source: https://github.com/tschettervictor/bsd-apps

Revision: `084ac45a5170613d6f57ed832e72fd09967971d7`

Upstream directory: `adguardhome`

This is a bundled, pinned subset for explicit administrative import and application. The repository license is retained in LICENSE. Installed packages are fetched from the jail package repository and are not pinned by this source revision. Runtime compatibility must be verified on the target FreeCORE image.

The original recipe and installer are retained as Bastillefile.upstream and adguardhome-install.sh.upstream. The active recipe fixes the application name, omits host-side CP and chmod, and invokes the adapted installer with `/bin/sh -e`. The FreeCORE API stages that fixed installer inside the jail before applying the recipe, without host-side copying into jail-controlled paths.

The adapted installer fails on command errors, copies a legacy /usr/local/etc/AdGuardHome.yaml only when it exists and no persistent configuration exists, and otherwise lets AdGuard Home initialize its configuration during setup. It restarts the service on application, including reapplication, and does not infer a reinstall merely from the required mount directories being present.

The service explicitly runs as root:wheel inside the jail, matching the FreeCORE ports revision e413f8eee6226fac3078e675718b564044545dd2 (www/adguardhome 0.107.69_3). That port specifies root for the privileged DNS port 53. No host sysctl or privilege settings are changed. The installer preserves dataset ownership and permissions and does not recursively change existing files. Runtime package versions may differ from this reviewed port; this adaptation is not a runtime acceptance or endorsement claim.

Before application, FreeCORE requires writable persistent mounts at /var/db/adguardhome and /usr/local/etc/adguardhome. Applying the template can modify those datasets; failed application does not roll them back. Existing application configuration is retained, including any previously changed web port.

The installer sets adguardhome_flags=-f so the package's daemon(8) supervisor detaches its standard descriptors. Without this flag, the FreeBSD package 0.107.77 supervisor retains the template job's output pipes after the recipe exits, leaving the job unfinished. The package's application log remains enabled. Reapplication resets this daemon flag along with the other service settings above.
