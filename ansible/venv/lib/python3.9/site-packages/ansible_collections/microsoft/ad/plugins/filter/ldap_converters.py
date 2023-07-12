# Copyright: (c) 2023, Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

import base64
import datetime
import struct
import typing as t
import uuid

from ansible.errors import AnsibleFilterError
from ansible.module_utils.common.collections import is_sequence


def per_sequence(func: t.Callable[[t.Any], t.Any]) -> t.Any:
    def wrapper(value: t.Any, *args: t.Any, **kwargs: t.Any) -> t.Any:
        if is_sequence(value):
            return [func(v, *args, **kwargs) for v in value]
        else:
            return func(value, *args, **kwargs)

    return wrapper


@per_sequence
def as_datetime(value: t.Any, format: str = "%Y-%m-%dT%H:%M:%S.%f%z") -> str:
    if isinstance(value, bytes):
        value = value.decode("utf-8")

    if isinstance(value, str):
        value = int(value)

    # FILETIME is 100s of nanoseconds since 1601-01-01. As Python does not
    # support nanoseconds the delta is number of microseconds.
    delta = datetime.timedelta(microseconds=value // 10)
    dt = datetime.datetime(year=1601, month=1, day=1, tzinfo=datetime.timezone.utc) + delta

    return dt.strftime(format)


@per_sequence
def as_guid(value: t.Any) -> str:
    if isinstance(value, bytes):
        guid = uuid.UUID(bytes_le=value)

    else:
        b_value = base64.b64decode(str(value))
        guid = uuid.UUID(bytes_le=b_value)

    return str(guid)


@per_sequence
def as_sid(value: t.Any) -> str:
    if isinstance(value, bytes):
        view = memoryview(value)
    else:
        b_value = base64.b64decode(value)
        view = memoryview(b_value)

    if len(view) < 8:
        raise AnsibleFilterError("Raw SID bytes must be at least 8 bytes long")

    revision = view[0]
    sub_authority_count = view[1]
    authority = struct.unpack(">Q", view[:8])[0] & ~0xFFFF000000000000

    view = view[8:]
    if len(view) < sub_authority_count * 4:
        raise AnsibleFilterError("Not enough data to unpack SID")

    sub_authorities: t.List[str] = []
    for dummy in range(sub_authority_count):
        auth = struct.unpack("<I", view[:4])[0]
        sub_authorities.append(str(auth))
        view = view[4:]

    return f"S-{revision}-{authority}-{'-'.join(sub_authorities)}"


class FilterModule:
    def filters(self) -> t.Dict[str, t.Callable]:
        return {
            "as_datetime": as_datetime,
            "as_guid": as_guid,
            "as_sid": as_sid,
        }
