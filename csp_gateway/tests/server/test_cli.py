import subprocess
import sys


def test_start_help():
    result = subprocess.run([sys.executable, "-m", "csp_gateway.server.cli", "--help"], capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr
    assert "Powered by Hydra" in result.stdout
