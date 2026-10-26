#!/usr/bin/env python3
"""Pick the tag a release's generated notes are compared against.

GitHub's generated release notes list the pull requests between a release tag
and a "previous" tag. Left to choose, GitHub takes the newest release tag that
is an ANCESTOR of the new one. Releases here are tagged on per-version release
branches cut from main, so no recent release tag is an ancestor of the next
one, and the choice falls back to a tag from the first weeks of the project:
every page then lists thousands of old pull requests. So the workflow names
the base itself, by lineage rather than by ancestry:

* a stable tag ``vX.Y.Z`` compares against the highest stable tag below
  ``X.Y.Z``;
* a prerelease tag ``vX.Y.Z-<label>.N`` compares against the prerelease of the
  same ``X.Y.Z`` line with the highest number below ``N`` (the label may
  change along a line: ``rc.1`` starts it and ``insider.2`` follows);
* the first prerelease of a line compares against the highest stable tag below
  its base, which is what that line adds over the last stable release.

Tags that do not follow either shape are ignored. When there is no candidate
the output is empty, and the release action falls back to GitHub's own choice.

Usage: ``release_previous_tag.py <tag>`` with the repository's tag names, one
per line (``refs/tags/`` prefixes allowed), on stdin. Prints the chosen tag.
"""

from __future__ import annotations

import re
import sys
from typing import Iterable, NamedTuple

_TAG = re.compile(r"^v(\d+)\.(\d+)\.(\d+)(?:-([a-z]+)\.(\d+))?$")


class ReleaseTag(NamedTuple):
    name: str
    base: tuple[int, int, int]
    # None for a stable tag; the prerelease's trailing number otherwise.
    number: int | None


def parse_tag(name: str) -> ReleaseTag | None:
    """Return the tag's base and prerelease number, or None for other shapes."""
    match = _TAG.match(name.strip().removeprefix("refs/tags/"))
    if not match:
        return None
    major, minor, patch, _label, number = match.groups()
    return ReleaseTag(
        name=match.group(0),
        base=(int(major), int(minor), int(patch)),
        number=None if number is None else int(number),
    )


def previous_tag(current: str, tags: Iterable[str]) -> str:
    """Return the tag *current*'s notes compare against, or "" when none fits."""
    this = parse_tag(current)
    if this is None:
        return ""
    known = [tag for tag in (parse_tag(name) for name in tags) if tag is not None]
    if this.number is not None:
        same_line = [
            tag
            for tag in known
            if tag.base == this.base and tag.number is not None and tag.number < this.number
        ]
        if same_line:
            return max(same_line, key=lambda tag: tag.number or 0).name
    stable = [tag for tag in known if tag.number is None and tag.base < this.base]
    return max(stable, key=lambda tag: tag.base).name if stable else ""


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: release_previous_tag.py <tag>  (tag names on stdin)", file=sys.stderr)
        return 2
    print(previous_tag(argv[1], sys.stdin.read().split()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
