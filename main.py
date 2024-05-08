#!/usr/bin/env python3
from __future__ import annotations

import json
import logging
import os
import urllib.request
from contextlib import ExitStack
from dataclasses import KW_ONLY, dataclass, field
from enum import Enum, auto, unique
from pathlib import Path
from re import Pattern, fullmatch
from tempfile import TemporaryDirectory
from typing import ClassVar, Iterable, Optional
from urllib.error import HTTPError
from zipfile import ZipFile, ZipInfo

LOG = logging.getLogger(__name__)
LOG.setLevel(logging.DEBUG)


def setup_logging(
    *,
    log_path: Optional[str | Path] = None,
    console_level: int = logging.INFO,
    file_level: int = logging.DEBUG,
    global_level: int = logging.INFO,
    append: bool = False,
) -> None:
    console_handler = logging.StreamHandler()
    console_handler.setLevel(console_level)
    handlers: list[logging.Handler] = [console_handler]
    if log_path:
        mode = "a" if append else "w"
        file_handler = logging.FileHandler(log_path, mode=mode)
        file_handler.setLevel(file_level)
        handlers.append(file_handler)
    logging.basicConfig(
        encoding="utf-8",
        style="$",
        format="$asctime $levelname $module:$funcName:$lineno - $message",
        datefmt="%Y-%m-%d %H:%M:%S",
        level=global_level,
        handlers=handlers,
    )
    logging.getLogger(__name__).debug("Logging initialized.")


@dataclass
class Release:
    tag: str
    asset_urls: dict[Path, str] = field(default_factory=dict)

    def matching_assets(self, pattern: Pattern[str]) -> Iterable[Path]:
        yield from (
            name for name in self.asset_urls if fullmatch(pattern, str(name))
        )

    def single_matching_asset(self, pattern: Pattern[str]) -> Path | None:
        result = None
        for name in self.matching_assets(pattern):
            if result is not None:
                raise RuntimeError(f"Multiple matches for pattern: {pattern}")
            result = name
        if result is None:
            LOG.warning(f"No files matching pattern: {pattern}")
        return result


@dataclass
class GitHubRepository:
    name: str
    _: KW_ONLY
    organization: str

    API_BASE_URL: ClassVar[str] = "https://api.github.com"
    RETRY_COUNT: ClassVar[int] = 3

    def __str__(self) -> str:
        return f"{self.organization}/{self.name}"

    def api_url(self) -> str:
        return f"{type(self).API_BASE_URL}/repos/{self}"

    def api_release_url(self, tag: str = "") -> str:
        endpoint = "latest" if not tag else f"tags/{tag}"
        return f"{self.api_url()}/releases/{endpoint}"

    def get_release(self, tag: str = "") -> Release | None:
        url = self.api_release_url(tag=tag)
        try:
            attempts = max(type(self).RETRY_COUNT, 0) + 1
            for attempt in range(attempts):
                with urllib.request.urlopen(url) as response:
                    if response.status == 200:
                        data = json.loads(response.read().decode())
                        return Release(
                            tag=data["tag_name"],
                            asset_urls={
                                Path(asset["name"]): asset[
                                    "browser_download_url"
                                ]
                                for asset in data.get("assets", [])
                            },
                        )
                    else:
                        LOG.warning(
                            f"[attempt {attempt+1}/{attempts}]"
                            f" Status {response.status} from: {url}"
                        )
            raise HTTPError(
                url,
                response.status,
                "only status 200 is accepted.",
                response.headers,
                None,
            )
        except Exception as ex:
            if isinstance(ex, HTTPError) and ex.code == 404:
                if tag:
                    LOG.warning(f"{self} has no release named {tag}")
                else:
                    LOG.warning(f"{self} has no releases.")
                return None
            LOG.exception("Exception when querying GitHub API: %s", url)
            raise
        return None


class SecurityException(Exception):
    """Exception raised for attepts to breach security."""

    pass


@dataclass
class EntryMetadata:
    mode: int
    is_directory: bool

    @staticmethod
    def from_ZipInfo(info: ZipInfo) -> EntryMetadata:
        return EntryMetadata(
            mode=(info.external_attr >> 16) & 0o777, is_directory=info.is_dir()
        )


# TODO: detect and check symlink paths
def extract_zip(
    archive: str | Path, *, destination: str | Path, strip_components: int = 0
) -> dict[Path, EntryMetadata]:
    destination = Path(destination).absolute()
    manifest: dict[Path, EntryMetadata] = {}
    with ZipFile(archive, "r") as zip_file:
        # all names shortest to longest... which for a given subtree is
        # effectively shallowest to deepest.
        max_strip = len(Path(os.path.commonpath(zip_file.namelist())).parts)
        if strip_components > max_strip:
            raise ValueError(
                f"Archive only has {max_strip} common root component(s), but"
                f" {strip_components} component(s) were requested to be"
                " stripped."
            )
        for name in sorted(zip_file.namelist(), key=len):
            entry = Path(name)
            if entry.is_absolute():
                raise SecurityException(
                    f'Zip file "{archive}" has entry with absolute'
                    f" path: {entry}"
                )
            entry = Path(*entry.parts[strip_components:])  # strip components
            extracted_path = (destination / entry).absolute()
            if not extracted_path.is_relative_to(destination):
                raise SecurityException(
                    f'Zip file "{archive}" has maliciously crafted entry'
                    ' attempting to utilize the "Zip Slip"'
                    f" vulnerability: {name}"
                )

            metadata = EntryMetadata.from_ZipInfo(zip_file.getinfo(name))
            manifest[extracted_path] = metadata
            temp_permissions = 0o700 if metadata.is_directory else 0o600
            if extracted_path.exists():
                extracted_path.chmod(temp_permissions)  # ensure modifiable

            with zip_file.open(name) as entry_file:
                if metadata.is_directory:
                    extracted_path.mkdir()
                else:
                    with open(extracted_path, "wb") as output_file:
                        output_file.write(entry_file.read())
            extracted_path.chmod(temp_permissions)  # ensure modifiable
    # apply proper permissions (deepest to shallowest)
    for path in sorted(
        manifest.keys(), key=lambda p: len(p.parts), reverse=True
    ):
        path.chmod(manifest[path].mode)
    return manifest


@unique
class ArchiveFormat(Enum):
    ZIP = auto()
    TGZ = auto()
    TAR = auto()


@dataclass
class Asset:
    pattern: Pattern[str]
    destination: Path
    archive_format: ArchiveFormat | None  # no default; explicit is clearer
    strip_archive_components: int = 0
    rename_file: str = ""

    def __post_init__(self) -> None:
        if self.destination.is_absolute():
            raise ValueError(
                f"Asset matching pattern {repr(self.pattern.pattern)} has"
                f" absolute path for its destination: {self.destination}"
            )


@dataclass
class ApplicationUpdater:
    repository: GitHubRepository
    assets: list[Asset]
    user_data: set[Path]
    # background_processes: list[list[str]]
    # main_process: list[str]

    def __post_init__(self) -> None:
        for path in self.user_data:
            if path.is_absolute():
                raise ValueError(f"User data path is an absolute path: {path}")

    def validate_release(self, release: Release) -> None:
        for asset in self.assets:
            name = release.single_matching_asset(asset.pattern)
            if not name:
                raise ValueError(
                    f"Release {release.tag} does not contain an asset that"
                    f" matches the pattern: {repr(asset.pattern.pattern)}"
                )
            if asset.archive_format:
                if asset.rename_file:
                    raise ValueError(
                        f"Release asset {repr(name)} is an archive, but"
                        " rename_file was specified."
                    )
            elif asset.strip_archive_components:
                raise ValueError(
                    f"Release asset {repr(name)} is not an archive, but"
                    " strip_archive_components was specified."
                )

    def update(
        self, install_directory: Path, *, tag: str = "", in_place: bool = False
    ) -> None:
        tag_file = install_directory / ".github_release_tag"
        release = self.repository.get_release(tag=tag)
        if not release:
            LOG.info(f"No release found for: {self.repository}")
            return
        installed_tag = tag_file.read_text().strip()
        if tag_file.exists() and installed_tag == release.tag:
            LOG.info(f'Installed tag "{installed_tag}" is the latest.')
            return
        self.validate_release(release)  # ensure release has what we need
        LOG.info(f'Updating tag from "{installed_tag}" to "{release.tag}"')
        with ExitStack() as stack:
            asset_directory = Path(stack.enter_context(TemporaryDirectory()))
            if in_place:
                staging_directory = install_directory
            else:
                staging_directory = Path(
                    stack.enter_context(TemporaryDirectory())
                )
            LOG.debug(f"Downloading assets into: {asset_directory}")
            LOG.debug(f"Staging into: {staging_directory}")
            for asset in self.assets:
                name = release.single_matching_asset(asset.pattern)
                if not name:
                    raise AssertionError(
                        "Unreachable code: asset already verified to exist."
                    )
                asset_url = release.asset_urls[name]
                staging_destination = staging_directory / asset.destination
                if asset.archive_format:
                    target_directory = asset_directory
                    target_file = target_directory / name
                else:
                    target_directory = staging_destination
                    target_file = target_directory / (
                        name if not asset.rename_file else asset.rename_file
                    )
                LOG.debug(f"Downloading {asset_url} to: {target_file}")
                urllib.request.urlretrieve(asset_url, target_file)

                target_directory.mkdir(parents=True, exist_ok=True)
                if asset.archive_format:
                    if asset.archive_format == ArchiveFormat.ZIP:
                        # TODO: accumulate manifest, log overwrites
                        LOG.debug(
                            f"Extracting {target_file} to:"
                            f" {staging_destination}"
                        )
                        extract_zip(
                            target_file,
                            destination=staging_destination,
                            strip_components=asset.strip_archive_components,
                        )
                        target_file.unlink()
                    else:
                        raise NotImplementedError(
                            f"Archive type {asset.archive_format}"
                        )
                else:
                    # TODO: add file to manifest
                    LOG.debug("TODO")
            if not in_place:
                # TODO: move it to the destination!
                LOG.error("UNIMPLEMENTED: move build when not in_place")
            # TODO: install, write out tag_file


# def make_pristine(path: str|Path, manifest: dict[Path, EntryMetadata])


def main() -> int:
    setup_logging(log_path="foo.txt", console_level=logging.DEBUG)
    # repository = GitHubRepository("Peacock", organization="thepeacockproject")
    # release = repository.get_release()
    # if release:
    #    print(f"Release Tag: {release.tag}")
    #    asset = release.single_matching_asset(re.compile(r"Peacock-v[^-]+\.zip"))
    #    if asset:
    #        print(f"Asset: {asset}")
    #        urllib.request.urlretrieve(release.asset_urls[asset], asset)
    #        extract_zip(asset, destination="output/", strip=1)
    # else:
    #    print("Failed to fetch release.")
    return 0


if __name__ == "__main__":
    import sys

    sys.exit(main())
