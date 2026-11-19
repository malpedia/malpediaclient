"""Typed response models for the Malpedia REST API.

The models describe the JSON objects returned by the client methods. Models
with `total=False` have keys that are not present in every response.
"""

from typing import Any, TypedDict

YaraRules = dict[str, dict[str, str]]
"""YARA rules keyed by TLP level, then by file name."""


class Version(TypedDict):
    """Current version of the Malpedia dataset."""

    version: int
    date: str


class FamilyMatch(TypedDict):
    """A family returned by a name search."""

    name: str
    alt_names: list[str]


class ActorMatch(TypedDict):
    """An actor returned by a name search."""

    name: str
    common_name: str
    synonyms: list[str]


class Family(TypedDict, total=False):
    """Metadata of one malware family."""

    uuid: str
    common_name: str
    alt_names: list[str]
    description: str
    urls: list[str]
    notes: list[Any]
    sources: list[Any]
    attribution: list[Any]
    library_entries: list[Any]
    updated: str


# Metadata attached to a threat actor, following the MISP threat actor galaxy. Functional syntax is
# needed because the keys contain hyphens. Other keys may appear for individual actors.
ActorMeta = TypedDict(
    "ActorMeta",
    {
        "attribution-confidence": str,
        "cfr-suspected-state-sponsor": str,
        "cfr-suspected-victims": list[str],
        "cfr-target-category": list[str],
        "cfr-type-of-incident": str,
        "country": str,
        "refs": list[str],
        "synonyms": list[str],
        "targeted-sector": list[str],
    },
    total=False,
)


class Actor(TypedDict, total=False):
    """Metadata of one threat actor."""

    uuid: str
    value: str
    description: str
    families: dict[str, Any]
    related: list[Any]
    meta: ActorMeta


class Sample(TypedDict):
    """A sample listed for a family."""

    sha256: str
    status: str
    version: str


class SampleInfo(TypedDict, total=False):
    """Presence and status of one sample."""

    md5: str
    sha256: str
    status: str
    family: str
    version: str
    winapi1024v1: str


class YaraFile(TypedDict):
    """A YARA rule file listed for a family."""

    path: str
    tlp: str
