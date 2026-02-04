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
    log_file.write_text("test log contents")

    symlink_name = "csp-gateway_20260101_120000.log"

    # Act
    handler = SymlinkFileHandler(
        filename=str(log_file),
        log_links_dir=str(log_links_dir),
        symlink_filename=symlink_name,
    )

    # Assert
    timestamped_link = log_links_dir / symlink_name
    latest_link = log_links_dir / "latest.log"

    assert timestamped_link.is_symlink()
    assert latest_link.is_symlink()

    assert timestamped_link.resolve() == log_file
    assert latest_link.resolve() == log_file

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
