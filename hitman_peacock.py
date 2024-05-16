#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
from re import compile

from automatic_updater import (
    ApplicationUpdater,
    ArchiveFormat,
    Asset,
    GitHubRepository,
    Process,
    setup_logging,
)


def main() -> int:
    setup_logging(Path(f"{Path(__file__).stem}.log"))
    updater = ApplicationUpdater(
        name="Peacock",
        repository=GitHubRepository(
            "Peacock", organization="thepeacockproject"
        ),
        assets=[
            Asset(
                pattern=compile(r"Peacock-v[^-]+\.zip"),
                archive_format=ArchiveFormat.ZIP,
                # destination=Path("."),
                strip_archive_components=1,
            )
        ],
        preserved_paths={
            Path("userdata"),
            Path("contracts"),
            Path("contractSessions"),
        },
        processes=[
            Process(["Start Server.cmd"]),
            Process(["PeacockPatcher.exe"]),
        ],
    )
    updater.update()
    updater.launch()
    return 0


if __name__ == "__main__":
    import sys

    sys.exit(main())
