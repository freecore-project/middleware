from middlewared.service import Service, private

# Tables whose sqlalchemy models were declared by the removed proprietary
# middlewared_truenas overlay (freecore/the internal development record). The tables may still
# exist in the database, but without a model _get_table() cannot resolve them,
# so datastore calls are intercepted here and answered with the values the
# overlay produced on an unlicensed single-node system.

FAILOVER_ROW = {'id': 1, 'disabled': True, 'master': False, 'timeout': 0}


class DatastoreStubService(Service):

    class Config:
        namespace = 'datastore.stub'

    @private
    async def handle_removed_tables(self, name, filters=None, options=None):
        if name == 'system.failover':
            if options and options.get('get'):
                return dict(FAILOVER_ROW)
            return [dict(FAILOVER_ROW)]
        if name == 'services.fibrechanneltotarget':
            return []
        return None

    @private
    async def handle_removed_tables_insert(self, name, data, options=None):
        if name in ('system.failover', 'services.fibrechanneltotarget'):
            return 1
        return None

    @private
    async def handle_removed_tables_update(self, name, id_or_filters, data, options=None):
        if name in ('system.failover', 'services.fibrechanneltotarget'):
            return data
        return None

    @private
    async def handle_removed_tables_delete(self, name, id_or_filters, options=None):
        if name in ('system.failover', 'services.fibrechanneltotarget'):
            return True
        return None
