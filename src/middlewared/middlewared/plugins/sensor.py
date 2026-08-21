from middlewared.service import Service, filterable
from middlewared.utils import filter_list


class SensorService(Service):
    """
    Stand-in for the removed proprietary sensor plugin (the internal development record).
    The webui maps sensor.query, so the namespace must answer; there is no
    supported sensor hardware on this system.
    """

    @filterable
    async def query(self, filters, options):
        return filter_list([], filters, options)
