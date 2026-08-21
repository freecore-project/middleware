def service_spn_targets(service_class, current_spns, netbiosname, domainname):
    """
    Expand a service class the same way Samba's retired
    ``net ads keytab add_update_ads`` command did.

    Prefer HOST SPNs already registered on the computer account.  Besides the
    short name and dNSHostName, this preserves additional DNS hostnames.  A
    newly-created or unusually sparse computer account falls back to the
    configured NetBIOS name and AD DNS domain.
    """
    hostnames = []
    seen = set()
    for spn in current_spns:
        try:
            registered_service, hostname = spn.split('/', 1)
        except ValueError:
            continue

        hostname = hostname.lower()
        if registered_service.casefold() != 'host' or hostname.casefold() in seen:
            continue

        seen.add(hostname.casefold())
        hostnames.append(hostname)

    if not hostnames:
        short = netbiosname.lower()
        hostnames = [short, f'{short}.{domainname.lower()}']

    service_class = service_class.lower()
    return [f'{service_class}/{hostname}' for hostname in hostnames]


def samba_keytab_sync_option(keytab_path):
    """Return Samba 4.24's complete machine-keytab synchronization contract."""
    return (
        f'sync machine password to keytab={keytab_path}:'
        'spn_prefixes=host:account_name:sync_spns:sync_kvno:machine_password'
    )
