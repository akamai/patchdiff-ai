import dataclasses
from types import UnionType
from typing import Any, Optional, TypeVar, Union, get_origin, get_args, dataclass_transform, get_type_hints

__all__ = ["defaultdataclass"]

T = TypeVar("T")
_marker = '__is_defaultdataclass__'


def _extract_base(typ: type[Any]) -> type[Any]:
    origin = get_origin(typ)

    if hasattr(typ, '__metadata__'):
        args = get_args(typ)
        if args:
            return _extract_base(args[0])

    if origin is Union:
        args = tuple(a for a in get_args(typ) if a is not type(None))
        if len(args) == 1:
            return _extract_base(args[0])
        return typ

    return typ


def _isinstance_generic(value: Any, typ: type[Any]) -> bool:
    try:
        return isinstance(value, typ)
    except TypeError:
        origin = get_origin(typ)
        return origin is not None and isinstance(value, origin)


def _is_defaultdataclass(cls: type) -> bool:
    return hasattr(cls, _marker)


def _safe_cast(value: Any, target: type[Any]) -> Any:
    base_type = _extract_base(target)

    if value is None:
        if _is_defaultdataclass(base_type):
            return base_type()
        else:
            return None

    if _isinstance_generic(value, base_type):
        return value

    origin = get_origin(base_type)
    if origin in (Union, UnionType):
        args = get_args(base_type)
        for option in args:
            try:
                return _safe_cast(value, option)  # recurse
            except (TypeError, ValueError):
                continue
        raise TypeError(
            f"cannot coerce {value!r} to any of "
            f"[{' | '.join(getattr(t, '__name__', str(t)) for t in args)}]"
        )

    if target is bytes:
        if isinstance(value, str):
            return value.encode()
        return bytes(value)
    if target is bytearray:
        if isinstance(value, str):
            return bytearray(value, "utf-8")
        return bytearray(value)
    if target is memoryview:
        if isinstance(value, str):
            return memoryview(value.encode())
        return memoryview(value)
    if target is str and isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value).decode()

    try:
        return target(value)
    except (ValueError, TypeError) as e:
        if _isinstance_generic(value, target):
            return value
        raise TypeError(f"Cannot assign {value!r} to {getattr(target, '__name__', str(target))}") from e


def _collect_annotations_from_mro(cls: type) -> dict[str, Any]:
    annotations = {}

    for base in reversed(cls.__mro__):
        if hasattr(base, '__annotations__'):
            annotations.update(base.__annotations__)

    return annotations


@dataclass_transform(
    field_specifiers=(dataclasses.field,)
)
def defaultdataclass(
        _cls=None, /, *, init=True, repr=True, eq=True, order=False,
        unsafe_hash=False, frozen=False, match_args=True,
        kw_only=False, slots=False, weakref_slot=False, new_members=False
) -> type[T]:
    def wrap(cls: type[T]) -> type[T]:
        orig_ann = dict(_collect_annotations_from_mro(cls))

        if not orig_ann:
            # If there are no types to coerce we don't need defaultdataclass
            return dataclasses.dataclass(
                init=init,
                repr=repr,
                eq=eq,
                order=order,
                unsafe_hash=unsafe_hash,
                frozen=frozen,
                match_args=match_args,
                kw_only=kw_only,
                slots=slots,
                weakref_slot=weakref_slot,
            )(cls)

        cls.__annotations__ = {k: Optional[v] for k, v in orig_ann.items()}

        base_map = {n: _extract_base(t) for n, t in orig_ann.items()}
        fields = frozenset(base_map)

        def __setattr__(self, name: str, value: Any, _bypass: bool = False) -> None:
            if frozen and not _bypass:
                raise dataclasses.FrozenInstanceError(f"cannot assign to field {name!r}")

            if name in fields:
                value = _safe_cast(value, base_map[name])

                if value is not None and not _isinstance_generic(value, base_map[name]):
                    raise TypeError(
                        f"{name} expects {base_map[name].__name__}, got {type(value).__name__}"
                    )

                object.__setattr__(self, name, value)
                return

            if new_members:
                object.__setattr__(self, name, value)

        def __post_init__(self) -> None:
            for name in orig_ann:
                if hasattr(self, name):
                    value = getattr(self, name)
                    self.__setattr__(name, value, True)

        def from_dict(self, data: dict[str, any], overwrite=False):
            for k, v in data.items():
                if hasattr(self, k):
                    if overwrite or getattr(self, k) is None:
                        setattr(self, k, v)
            return self

        def to_dict(self):
            return dataclasses.asdict(self)

        for name in orig_ann:
            if not hasattr(cls, name) or name not in cls.__dict__:
                setattr(cls, name, dataclasses.field(default=None))

        if hasattr(cls, '__post_init__'):
            original_post_init = cls.__post_init__

            def chained_post_init(self):
                __post_init__(self)
                original_post_init(self)

            cls.__post_init__ = chained_post_init
        else:
            cls.__post_init__ = __post_init__

        cls.from_dict = from_dict
        cls.to_dict = to_dict

        # Apply dataclass decorator
        cls = dataclasses.dataclass(
            init=init,
            repr=repr,
            eq=eq,
            order=order,
            unsafe_hash=unsafe_hash,
            frozen=frozen,
            match_args=match_args,
            kw_only=kw_only,
            slots=slots,
            weakref_slot=weakref_slot,
        )(cls)

        cls.__setattr__ = __setattr__
        cls.__annotations__ = orig_ann
        cls.__is_defaultdataclass__ = True
        return cls

    return wrap if _cls is None else wrap(_cls)
