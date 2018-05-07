class SettingsDict(dict):
    def __getattr__(self, name):
        if name not in self:
            raise AttributeError

        return self[name]

    def __setitem__(self, key, value):
        raise AttributeError('SettingsDict properties are immutable')
