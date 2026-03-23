import logging
from unittest.mock import patch

from csp_gateway.server.shared.symlink_file_handler import SymlinkFileHandler


def test_handler_creates_symlinks(tmp_path):
    """
    SymlinkFileHandler should create:
    - a timestamped symlink
    - a latest.log symlink
    """

    # Arrange
    output_dir = tmp_path / "hydra_output"
    log_links_dir = tmp_path / "job_log_links"

    output_dir.mkdir()
    log_links_dir.mkdir()

    log_file = output_dir / "csp-gateway.log"

    symlink_name = "csp-gateway_20260101_120000.log"

    # Act
    handler = SymlinkFileHandler(
        filename=str(log_file),
        log_links_dir=str(log_links_dir),
        symlink_filename=symlink_name,
    )

    # Assert
    assert log_file.exists()

    timestamped_link = log_links_dir / symlink_name
    latest_link = log_links_dir / "latest.log"

    assert timestamped_link.is_symlink()
    assert latest_link.is_symlink()

    assert timestamped_link.resolve() == log_file.resolve()
    assert latest_link.resolve() == log_file.resolve()

    handler.close()


def test_handler_creates_log_links_dir_if_missing(tmp_path):
    output_dir = tmp_path / "hydra_output"
    output_dir.mkdir()

    log_file = output_dir / "csp-gateway.log"
    log_file.write_text("log")

    log_links_dir = tmp_path / "missing_log_links"

    handler = SymlinkFileHandler(
        filename=str(log_file),
        log_links_dir=str(log_links_dir),
        symlink_filename="test.log",
    )

    assert log_links_dir.exists()
    assert log_links_dir.is_dir()

    handler.close()


def test_handler_writes_logs_through_symlink(tmp_path):
    output_dir = tmp_path / "hydra_output"
    output_dir.mkdir()

    log_file = output_dir / "csp-gateway.log"
    log_links_dir = tmp_path / "log_links"

    handler = SymlinkFileHandler(
        filename=str(log_file),
        log_links_dir=str(log_links_dir),
        symlink_filename="test.log",
    )

    test_logger = logging.getLogger("test_symlink_logger")
    test_logger.addHandler(handler)
    test_logger.setLevel(logging.INFO)

    test_logger.info("Test log message")
    handler.flush()

    latest_symlink = log_links_dir / "latest.log"
    assert latest_symlink.exists()
    assert latest_symlink.is_symlink()

    content = latest_symlink.read_text()
    assert "Test log message" in content

    handler.close()
    test_logger.removeHandler(handler)


def test_latest_symlink_updates_on_new_handler(tmp_path):
    output_dir1 = tmp_path / "run1"
    output_dir2 = tmp_path / "run2"
    output_dir1.mkdir()
    output_dir2.mkdir()

    log_links_dir = tmp_path / "log_links"

    handler1 = SymlinkFileHandler(
        filename=str(output_dir1 / "csp-gateway.log"),
        log_links_dir=str(log_links_dir),
        symlink_filename="run1.log",
    )

    latest = log_links_dir / "latest.log"
    assert latest.is_symlink()
    assert latest.resolve() == (output_dir1 / "csp-gateway.log").resolve()

    handler1.close()

    handler2 = SymlinkFileHandler(
        filename=str(output_dir2 / "csp-gateway.log"),
        log_links_dir=str(log_links_dir),
        symlink_filename="run2.log",
    )

    assert latest.is_symlink()
    assert latest.resolve() == (output_dir2 / "csp-gateway.log").resolve()

    handler2.close()


def test_handler_logs_error_when_directory_creation_fails(tmp_path, caplog):
    output_dir = tmp_path / "hydra_output"
    output_dir.mkdir()
    log_file = output_dir / "csp-gateway.log"

    with patch("pathlib.Path.mkdir", side_effect=PermissionError("Permission denied")):
        with caplog.at_level(logging.ERROR):
            handler = SymlinkFileHandler(
                filename=str(log_file),
                log_links_dir="/nonexistent/readonly/dir",
                symlink_filename="test.log",
            )

    assert "Failed to create symlink directory" in caplog.text
    handler.close()


def test_handler_logs_error_when_target_does_not_exist(tmp_path, caplog):
    from pathlib import Path

    target = tmp_path / "nonexistent.log"
    symlink_path = tmp_path / "link.log"

    with caplog.at_level(logging.ERROR):
        SymlinkFileHandler._create_file_symlink(target, symlink_path)

    assert "Target for symlink does not exist" in caplog.text
    assert not symlink_path.exists()


def test_handler_removes_existing_tmp_symlink(tmp_path):
    output_dir = tmp_path / "hydra_output"
    output_dir.mkdir()

    log_file = output_dir / "csp-gateway.log"
    log_file.write_text("log content")

    log_links_dir = tmp_path / "log_links"
    log_links_dir.mkdir()

    stale_tmp = log_links_dir / "test.log.tmp"
    stale_tmp.symlink_to(log_file)

    handler = SymlinkFileHandler(
        filename=str(log_file),
        log_links_dir=str(log_links_dir),
        symlink_filename="test.log",
    )

    assert not stale_tmp.exists()
    assert (log_links_dir / "test.log").is_symlink()

    handler.close()


def test_handler_logs_error_when_symlink_creation_fails(tmp_path, caplog):
    from pathlib import Path

    target = tmp_path / "target.log"
    target.write_text("content")
    symlink_path = tmp_path / "link.log"

    with patch.object(Path, "symlink_to", side_effect=OSError("Symlink failed")):
        with caplog.at_level(logging.ERROR):
            SymlinkFileHandler._create_file_symlink(target, symlink_path)

    assert "Failed to create symlink" in caplog.text
