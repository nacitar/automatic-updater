#!/usr/bin/env python3
from __future__ import annotations

import json
import logging
import urllib.request
from contextlib import ExitStack
from dataclasses import KW_ONLY, dataclass, field
from enum import Enum, auto, unique
from os.path import commonpath, dirname, normpath, pardir
from pathlib import Path
from re import Pattern, fullmatch
from shutil import rmtree
from tempfile import TemporaryDirectory
from types import TracebackType
from typing import ClassVar, Iterable, Optional, Type
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


# TODO: should this extend BadZipFile?  Probably not once other formats work.
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


@dataclass(frozen=True)
class PathMetadata:
    permissions: int
    is_directory: bool


@dataclass(frozen=True)
class ZipEntry:
    name: str
    path: Path
    metadata: PathMetadata


def delete_path(path: Path) -> None:
    if path.exists():
        if path.is_dir():
            LOG.warning(f"Deleting directory: {path}")
            path.chmod(0o700)
            rmtree(path)
        else:
            LOG.warning(f"Deleting file: {path}")
            path.chmod(0o600)
            path.unlink()


def merge_manifest(manifest: set[Path], destination: set[Path]) -> None:
    overlap = destination & manifest
    for path in overlap:
        LOG.warning(
            f"Path {path} was already installed by an earlier package but has"
            " been overwritten by a later one."
        )
    destination |= manifest


# TODO: symlinks?  check their targets?
class ZipPackage:
    def __init__(self, path: Path):
        self.path = path.resolve()
        self.__error_prefix = f'Zip archive "{self.path}"'
        self._zip_file = ZipFile(self.path, "r")
        common_root: str | None = None
        entries: list[ZipEntry] = []
        processed_paths: set[Path] = set()
        for name in self._zip_file.namelist():
            info = self._zip_file.getinfo(name)
            is_directory = info.is_dir()
            permissions = (info.external_attr >> 16) & 0o777
            # GREATLY simplifying logic by ensuring basic access for owner
            permissions |= 0o700 if is_directory else 0o600
            path = Path(normpath(name))
            if path in processed_paths:
                raise AssertionError(
                    f"{self.__error_prefix} has more than one entry that"
                    f" refers to the same path: {path}"
                )
            processed_paths.add(path)
            if path.is_absolute():
                raise SecurityException(
                    f"{self.__error_prefix} has entry with an absolute"
                    f" path: {path}"
                )
            if pardir in path.parts:
                raise SecurityException(
                    f"{self.__error_prefix} has maliciously crafted entry"
                    f' attempting the "Zip Slip" vulnerability: {path}'
                )
            if common_root is None:
                common_root = str(path)
                if not is_directory:
                    # using dirname instead of Path.parent because if there's
                    # no parent it gives "" instead of "."
                    common_root = dirname(str(path))
            else:
                common_root = commonpath([common_root, str(path)])

            entries.append(
                ZipEntry(
                    name=name,
                    path=path,
                    metadata=PathMetadata(
                        permissions=(info.external_attr >> 16) & 0o777,
                        is_directory=is_directory,
                    ),
                )
            )
        # for a given directory subtree, this order ensures you'll always
        # process parent paths before child paths.
        self._entries = sorted(
            entries, key=lambda entry: len(entry.path.parts)
        )
        self._common_root = Path(common_root or "")

    @property
    def common_root(self) -> Path:
        return Path(self._common_root)

    @property
    def common_root_depth(self) -> int:
        return len(self._common_root.parts)

    def extract(
        self,
        destination: Path,
        *,
        strip_components: int = 0,
    ) -> set[Path]:
        if strip_components > self.common_root_depth:
            raise ValueError(
                f"{self.__error_prefix} only has {self.common_root_depth}"
                f" common root component(s), but {strip_components}"
                " component(s) were requested to be stripped."
            )
        destination = destination.resolve()
        manifest: set[Path] = set()
        for entry in self._entries:
            stripped_path = Path(*entry.path.parts[strip_components:])
            manifest.add(stripped_path)
            installed_path = destination / stripped_path
            with self._zip_file.open(entry.name) as entry_file:
                if installed_path.exists():
                    LOG.warning(
                        f"Removing already existing path: {installed_path}"
                    )
                    delete_path(installed_path)
                if entry.metadata.is_directory:
                    installed_path.mkdir(
                        mode=entry.metadata.permissions, parents=True
                    )
                else:
                    # safety for if directories aren't distinct entries
                    # in the zip and only files exist (non-standard)
                    installed_path.parent.mkdir(parents=True, exist_ok=True)
                    with open(installed_path, "wb") as output_file:
                        output_file.write(entry_file.read())
                    installed_path.chmod(entry.metadata.permissions)
        return manifest

    def __enter__(self) -> ZipPackage:
        self._zip_file.__enter__()
        return self

    def __exit__(
        self,
        exc_type: Type[BaseException] | None,
        exc_value: BaseException | None,
        exc_traceback: TracebackType | None,
    ) -> None:
        self._zip_file.__exit__(exc_type, exc_value, exc_traceback)

    def close(self) -> None:
        self._zip_file.close()


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
    preserved_paths: set[Path]
    # background_processes: list[list[str]]
    # main_process: list[str]

    def __post_init__(self) -> None:
        for path in self.preserved_paths:
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

    # TODO: add option to delete things in destination that aren't in the
    # full_manifest or user_data (maybe rename that to "keep"?)
    # Maybe remove in_place and make it always True?  Ensure install_directory
    # exists too?
    def update(
        self,
        install_directory: Path,
        *,
        tag: str = "",
        staging_directory: Path | None = None,
    ) -> None:
        install_directory = install_directory.resolve()
        if staging_directory:
            staging_directory = staging_directory.resolve()
            if staging_directory == install_directory:
                raise ValueError(
                    "staging_directory refers to the same path as"
                    f" install_directory: {staging_directory}"
                )
        tag_file = install_directory / ".github_release_tag"
        release = self.repository.get_release(tag=tag)
        if not release:
            LOG.info(f"No release found for: {self.repository}")
            return
        installed_tag = (
            tag_file.read_text().strip() if tag_file.exists() else ""
        )
        if installed_tag == release.tag:
            LOG.info(f'Installed tag "{installed_tag}" is the latest.')
            return
        self.validate_release(release)  # ensure release has what we need
        LOG.info(f'Updating tag from "{installed_tag}" to "{release.tag}"')
        full_manifest: set[Path] = set()
        with ExitStack() as stack:
            asset_directory = Path(stack.enter_context(TemporaryDirectory()))
            staging_directory = Path(
                stack.enter_context(TemporaryDirectory(dir=staging_directory))
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
                        LOG.debug(
                            f"Extracting {target_file} to:"
                            f" {staging_destination}"
                        )
                        package = ZipPackage(target_file)
                        manifest = package.extract(
                            staging_destination,
                            strip_components=asset.strip_archive_components,
                        )
                        target_file.unlink()
                    else:
                        raise NotImplementedError(
                            f"Archive type {asset.archive_format}"
                        )
                else:
                    manifest = {target_file}
                merge_manifest(manifest, destination=full_manifest)

            LOG.debug("Processing preserved paths...")
            for path in self.preserved_paths:
                preserved_path = install_directory / path
                target_path = staging_directory / path
                delete_path(target_path)
                preserved_path.rename(target_path)
                merge_manifest({target_path}, destination=full_manifest)
            LOG.debug("Deleting old installation...")
            delete_path(install_directory)
            LOG.debug("Moving staging to the install directory...")
            staging_directory.rename(install_directory)
            tag_file.write_text(release.tag)
        LOG.debug(f"Successfully updated to release: {release.tag}")


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
