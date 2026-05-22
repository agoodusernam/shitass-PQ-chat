import threading
from typing import TypeVar, overload
from collections.abc import MutableMapping, Iterator

K = TypeVar("K")
V = TypeVar("V")
T = TypeVar("T")


class ThreadSafeDict(MutableMapping[K, V]):
    """A dict wrapper that serialises all access with an internal RLock.

    NOTE: Individual operations are atomic, but compound check-then-act
    patterns (e.g. 'if key in d: use d[key]') are still NOT atomic unless
    you use the .lock context manager explicitly.
    """
    
    def __init__(self, *args, **kwargs) -> None:
        self._data: dict[K, V] = dict(*args, **kwargs)  # ty:ignore[invalid-assignment]
        self.lock = threading.RLock()  # RLock so the same thread can re-enter
    
    def __getitem__(self, key: K) -> V:
        with self.lock:
            return self._data[key]
    
    def __setitem__(self, key: K, value: V) -> None:
        with self.lock:
            self._data[key] = value
    
    def __delitem__(self, key: K) -> None:
        with self.lock:
            del self._data[key]
    
    def __iter__(self) -> Iterator[K]:
        with self.lock:
            return iter(list(self._data))  # snapshot so iteration is safe
    
    def __len__(self) -> int:
        with self.lock:
            return len(self._data)
    
    def __contains__(self, key: object) -> bool:
        with self.lock:
            return key in self._data
    
    def clear(self) -> None:
        with self.lock:
            self._data.clear()
    
    @overload
    def get(self, key: K, default: None = None) -> V | None: ...
    
    @overload
    def get(self, key: K, default: T) -> T | V: ...
    
    def get(self, key: K, default: T | None = None) -> V | T | None:
        with self.lock:
            return self._data.get(key, default)
    
    def pop(self, key: K, *args):
        with self.lock:
            return self._data.pop(key, *args)
