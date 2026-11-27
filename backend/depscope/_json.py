import json
from typing import cast


class InvalidPayload(ValueError):
    pass


def _unique_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise InvalidPayload("duplicate_key")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise InvalidPayload("invalid_constant")


def decode_json(data: str | bytes) -> object:
    try:
        return cast(
            object,
            json.loads(data, object_pairs_hook=_unique_keys, parse_constant=_reject_constant),
        )
    except (ValueError, RecursionError) as exc:
        raise InvalidPayload("invalid_json") from exc


def object_value(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise InvalidPayload("expected_object")
    return cast(dict[str, object], value)


def array_value(value: object) -> list[object]:
    if not isinstance(value, list):
        raise InvalidPayload("expected_array")
    return cast(list[object], value)
