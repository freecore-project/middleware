class Configuration:
    def __init__(self):
        self._trains = {}

    def SystemManifest(self):
        return None

    def CurrentTrain(self):
        return ''

    def LoadTrainsConfig(self):
        pass

    def AvailableTrains(self):
        return {}

    def UpdateServerMaster(self):
        return ''

    def GetChangeLog(self, train=None):
        return None
