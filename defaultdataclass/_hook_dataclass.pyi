# defaultdataclass.pyi
from dataclasses import dataclass as _dc
from typing import Callable, overload, TypeVar
from typing_extensions import dataclass_transform

T = TypeVar("T")


@dataclass_transform(field_specifiers=(_dc.field,))
@overload
def defaultdataclass(_cls=..., /, *, init=..., repr=..., eq=..., order=...,
        unsafe_hash=..., frozen=..., match_args=...,
        kw_only=..., slots=..., weakref_slot=..., new_members=...) -> type[T]: ...
