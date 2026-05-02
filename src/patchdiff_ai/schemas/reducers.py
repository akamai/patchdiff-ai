"""LangGraph reducers used in Annotated state fields."""

from typing import Iterable, TypeVar

from langgraph.graph import add_messages as _add_messages

T = TypeVar("T")

# Re-export so node modules can import everything from one place.
add_messages = _add_messages


def append_list(left: list[T] | None, right: list[T] | T | None) -> list[T]:
    """Concat reducer; tolerates None and scalar-on-right."""
    base: list[T] = list(left) if left else []
    if right is None:
        return base
    if isinstance(right, list):
        base.extend(right)
    else:
        base.append(right)
    return base


def replace(_left: T, right: T) -> T:
    """Last-write-wins reducer."""
    return right


def union_set(left: set[T] | None, right: Iterable[T] | None) -> set[T]:
    base: set[T] = set(left) if left else set()
    if right:
        base.update(right)
    return base
