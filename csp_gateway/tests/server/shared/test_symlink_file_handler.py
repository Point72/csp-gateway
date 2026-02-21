import logging

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
