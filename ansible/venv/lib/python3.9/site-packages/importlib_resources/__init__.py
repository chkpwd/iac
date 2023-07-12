"""Read resources contained within a package."""

from ._common import (
    as_file,
    files,
)

from importlib_resources._py3 import (
    Package,
    Resource,
    contents,
    is_resource,
    open_binary,
    open_text,
    path,
    read_binary,
    read_text,
)
from importlib_resources.abc import ResourceReader


__all__ = [
    'Package',
    'Resource',
    'ResourceReader',
    'as_file',
    'contents',
    'files',
    'is_resource',
    'open_binary',
    'open_text',
    'path',
    'read_binary',
    'read_text',
]
