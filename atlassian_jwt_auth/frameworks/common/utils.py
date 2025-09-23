from typing import Any


class SettingsDict(dict):
    def __getattr__(self, name: str) -> Any:
        if name not in self:
            raise AttributeError

        return self[name]

    def __setitem__(self, key: Any, value: Any) -> None:
        raise AttributeError('SettingsDict properties are immutable')

    def _hash_key(self) -> frozenset[Any]:
        keys_and_values = []
        for key, value in self.items():
            if isinstance(value, set):
                value = frozenset(value)
            keys_and_values.append("%s %s" % (key, hash(value)))
        return frozenset(keys_and_values)

    def __hash__(self) -> int:
        return hash(self._hash_key())

    def __eq__(self, other) -> bool:
        return hash(self) == hash(other)
