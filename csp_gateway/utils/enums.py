from enum import Enum


class ReadWriteMode(str, Enum):
    """Enum representing whether a component is set to read, write, or both."""

    READ = "READ"
    WRITE = "WRITE"
    READ_AND_WRITE = "READ_AND_WRITE"
