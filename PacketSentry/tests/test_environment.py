"""
Unit test for PacketSentry environment verification.
"""

import unittest
from analyzer.environment import find_tshark_binary, get_tshark_version, check_python_environment, validate_environment

class TestEnvironment(unittest.TestCase):
    def test_find_tshark(self):
        tshark_path = find_tshark_binary()
        self.assertIsNotNone(tshark_path, "Tshark binary should be located on system or in standard directories")

    def test_tshark_version(self):
        tshark_path = find_tshark_binary()
        if tshark_path:
            ver = get_tshark_version(tshark_path)
            self.assertIsNotNone(ver, "Should be able to retrieve Tshark version")
            self.assertIn("TShark", ver, "Version output should contain 'TShark'")

    def test_python_packages(self):
        py_env = check_python_environment()
        self.assertIn("pandas", py_env["packages"])
        self.assertTrue(py_env["packages"]["pandas"]["installed"], "Pandas must be installed")
        self.assertIn("plotly", py_env["packages"])
        self.assertTrue(py_env["packages"]["plotly"]["installed"], "Plotly must be installed")

if __name__ == "__main__":
    unittest.main()
