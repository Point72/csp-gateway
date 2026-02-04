import logging
from pathlib import Path

__all__ = ["SymlinkFileHandler"]

log = logging.getLogger(__name__)


class SymlinkFileHandler(logging.FileHandler):
    def __init__(
        self,
        filename: str,
        log_links_dir: str,
        symlink_filename: str,
        *args,
        **kwargs,
    ):
        self.log_links_dir = Path(log_links_dir)
        self.symlink_filename = symlink_filename

        super().__init__(filename, *args, **kwargs)

        try:
            self.log_links_dir.mkdir(parents=True, exist_ok=True)
            log.debug("Ensured symlink directory exists: %s", self.log_links_dir)

            target = Path(self.baseFilename).resolve()

            # Timestamped symlink
            named_link = self.log_links_dir / self.symlink_filename

            self._create_file_symlink(target, named_link)

            # Latest symlink
            self._create_file_symlink(target, self.log_links_dir / "latest.log")

        except Exception:
            log.exception("Failed to create log symlink(s)")

    @staticmethod
    def _create_file_symlink(target: Path, symlink_path: Path) -> None:
        if not target.exists():
            log.error("Target for symlink does not exist: %s", target)
            return

        tmp = symlink_path.with_suffix(symlink_path.suffix + ".tmp")

        try:
            if tmp.exists() or tmp.is_symlink():
                tmp.unlink()

            tmp.symlink_to(target)
            tmp.replace(symlink_path)

            log.info("Created symlink %s -> %s", symlink_path, target)

        except Exception:
            log.exception("Failed to create symlink %s", symlink_path)
