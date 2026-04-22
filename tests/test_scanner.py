import unittest
from unittest.mock import patch, MagicMock
from modules.security.scanner import ServerScanner

class TestServerScanner(unittest.TestCase):

    # ─── FIREWALL ───
    @patch('modules.security.scanner.ServerScanner._run_cmd')
    def test_firewall_inactive(self, mock_run_cmd):
        mock_run_cmd.return_value = ("Status: inactive", "")
        result = ServerScanner._check_firewall()
        self.assertTrue(any("Tidak Aktif" in r for r in result))

    @patch('modules.security.scanner.ServerScanner._run_cmd')
    def test_firewall_active(self, mock_run_cmd):
        mock_run_cmd.return_value = ("Status: active", "")
        result = ServerScanner._check_firewall()
        self.assertTrue(any("Aktif" in r and "🟢" in r for r in result))

    # ─── SSH ───
    @patch('modules.security.scanner.ServerScanner._run_cmd')
    def test_ssh_vulnerable(self, mock_run_cmd):
        mock_run_cmd.return_value = ("permitrootlogin yes\npasswordauthentication yes", "")
        result = ServerScanner._check_ssh()
        self.assertTrue(any("Root Login Diizinkan" in r for r in result))
        self.assertTrue(any("Password Authentication Aktif" in r for r in result))

    @patch('modules.security.scanner.ServerScanner._run_cmd')
    def test_ssh_secure(self, mock_run_cmd):
        mock_run_cmd.return_value = ("permitrootlogin no\npasswordauthentication no", "")
        result = ServerScanner._check_ssh()
        self.assertTrue(any("Konfigurasi Aman" in r for r in result))

    # ─── PORTS ───
    @patch('modules.security.scanner.ServerScanner._run_cmd')
    def test_ports_exposed(self, mock_run_cmd):
        mock_run_cmd.return_value = ("tcp   LISTEN 0      128    0.0.0.0:22    0.0.0.0:*\ntcp   LISTEN 0      128    0.0.0.0:80    0.0.0.0:*", "")
        result = ServerScanner._check_ports()
        self.assertTrue(any("22" in r and "80" in r for r in result))

    @patch('modules.security.scanner.ServerScanner._run_cmd')
    def test_ports_clean(self, mock_run_cmd):
        mock_run_cmd.return_value = ("", "")
        result = ServerScanner._check_ports()
        self.assertEqual(len(result), 0)

    # ─── SERVICES ───
    @patch('modules.security.scanner.ServerScanner._run_cmd')
    def test_services_failed(self, mock_run_cmd):
        mock_run_cmd.return_value = ("nginx.service   loaded failed failed A high performance web server", "")
        result = ServerScanner._check_services()
        self.assertTrue(any("1 service" in r for r in result))

    @patch('modules.security.scanner.ServerScanner._run_cmd')
    def test_services_healthy(self, mock_run_cmd):
        mock_run_cmd.return_value = ("0 loaded units listed.", "")
        result = ServerScanner._check_services()
        self.assertTrue(any("Semua Normal" in r for r in result))

    # ─── FILE INTEGRITY MONITORING ───
    @patch('modules.security.scanner.ServerScanner._save_fim_snapshot')
    @patch('modules.security.scanner.ServerScanner._load_fim_snapshot')
    @patch('modules.security.scanner.ServerScanner._hash_file')
    @patch('modules.security.scanner.ServerScanner._run_cmd')
    def test_fim_first_run(self, mock_run_cmd, mock_hash, mock_load, mock_save):
        """Saat pertama kali, FIM akan membuat snapshot awal"""
        mock_load.return_value = {}
        mock_run_cmd.return_value = ("EXISTS", "")
        mock_hash.return_value = "abc123hash"
        
        result = ServerScanner._check_file_integrity()
        self.assertTrue(any("Snapshot awal" in r for r in result))
        mock_save.assert_called_once()

    @patch('modules.security.scanner.ServerScanner._save_fim_snapshot')
    @patch('modules.security.scanner.ServerScanner._load_fim_snapshot')
    @patch('modules.security.scanner.ServerScanner._hash_file')
    @patch('modules.security.scanner.ServerScanner._run_cmd')
    def test_fim_detects_change(self, mock_run_cmd, mock_hash, mock_load, mock_save):
        """FIM harus mendeteksi perubahan hash file"""
        mock_load.return_value = {
            "/etc/passwd": {"hash": "old_hash_value", "checked_at": "2026-01-01T00:00:00"}
        }
        mock_run_cmd.return_value = ("EXISTS", "")
        mock_hash.return_value = "new_different_hash"
        
        result = ServerScanner._check_file_integrity()
        self.assertTrue(any("perubahan" in r.lower() for r in result))

    @patch('modules.security.scanner.ServerScanner._save_fim_snapshot')
    @patch('modules.security.scanner.ServerScanner._load_fim_snapshot')
    @patch('modules.security.scanner.ServerScanner._hash_file')
    @patch('modules.security.scanner.ServerScanner._run_cmd')
    def test_fim_no_change(self, mock_run_cmd, mock_hash, mock_load, mock_save):
        """FIM harus mengembalikan status aman jika hash tidak berubah"""
        mock_load.return_value = {
            "/etc/passwd": {"hash": "same_hash", "checked_at": "2026-01-01T00:00:00"}
        }
        mock_run_cmd.return_value = ("EXISTS", "")
        mock_hash.return_value = "same_hash"
        
        result = ServerScanner._check_file_integrity()
        self.assertTrue(any("aman" in r.lower() for r in result))

    # ─── AUTHORIZED KEYS AUDIT ───
    @patch('modules.security.scanner.ServerScanner._run_cmd')
    def test_authorized_keys_suspicious(self, mock_run_cmd):
        """Terdeteksi banyak SSH key — curigai backdoor"""
        def side_effect(cmd):
            if "for f in" in cmd:
                return "/root/.ssh/authorized_keys", ""
            if "grep -c" in cmd:
                return "5", ""
            return "", ""
        mock_run_cmd.side_effect = side_effect
        
        result = ServerScanner._check_authorized_keys()
        self.assertTrue(any("🔴" in r for r in result))

    @patch('modules.security.scanner.ServerScanner._run_cmd')
    def test_authorized_keys_clean(self, mock_run_cmd):
        """Tidak ada authorized keys — aman"""
        mock_run_cmd.return_value = ("", "")
        result = ServerScanner._check_authorized_keys()
        self.assertTrue(any("Tidak ditemukan" in r for r in result))

    # ─── OUTDATED PACKAGES ───
    @patch('modules.security.scanner.ServerScanner._run_cmd')
    def test_packages_outdated(self, mock_run_cmd):
        """Ada paket keamanan yang expired"""
        def side_effect(cmd):
            if "which apt-get" in cmd:
                return "/usr/bin/apt-get", ""
            if "grep -i 'security'" in cmd:
                return "Inst libssl3 [3.0.2-0ubuntu1.14] (3.0.2-0ubuntu1.15 Ubuntu:22.04/jammy-security)", ""
            if "grep -ci 'security'" in cmd:
                return "3", ""
            return "", ""
        mock_run_cmd.side_effect = side_effect
        
        result = ServerScanner._check_outdated_packages()
        self.assertTrue(any("3 paket" in r for r in result))

    @patch('modules.security.scanner.ServerScanner._run_cmd')
    def test_packages_up_to_date(self, mock_run_cmd):
        """Semua paket sudah terbaru"""
        def side_effect(cmd):
            if "which apt-get" in cmd:
                return "/usr/bin/apt-get", ""
            if "grep -ci 'security'" in cmd:
                return "0", ""
            if "grep -i 'security'" in cmd:
                return "", ""
            return "", ""
        mock_run_cmd.side_effect = side_effect
        
        result = ServerScanner._check_outdated_packages()
        self.assertTrue(any("sudah terbaru" in r for r in result))

    # ─── FULL SCAN ───
    @patch('modules.security.scanner.ServerScanner._check_outdated_packages')
    @patch('modules.security.scanner.ServerScanner._check_authorized_keys')
    @patch('modules.security.scanner.ServerScanner._check_file_integrity')
    @patch('modules.security.scanner.ServerScanner._check_services')
    @patch('modules.security.scanner.ServerScanner._check_ports')
    @patch('modules.security.scanner.ServerScanner._check_ssh')
    @patch('modules.security.scanner.ServerScanner._check_firewall')
    def test_scan_all_assembles_report(self, mock_fw, mock_ssh, mock_ports, 
                                        mock_svc, mock_fim, mock_keys, mock_pkg):
        """scan_all harus merakit semua sub-scan menjadi satu laporan"""
        mock_fw.return_value = ["🟢 Firewall OK"]
        mock_ssh.return_value = ["🟢 SSH OK"]
        mock_ports.return_value = []
        mock_svc.return_value = ["🟢 Services OK"]
        mock_fim.return_value = ["🟢 FIM OK"]
        mock_keys.return_value = ["🟢 Keys OK"]
        mock_pkg.return_value = ["🟢 Packages OK"]
        
        report = ServerScanner.scan_all()
        self.assertIn("HEIMDALL", report)
        self.assertIn("Firewall OK", report)
        self.assertIn("FIM OK", report)
        self.assertIn("Keys OK", report)
        self.assertIn("Packages OK", report)

    # ─── SILENT SCAN ───
    @patch('modules.security.scanner.ServerScanner._check_outdated_packages')
    @patch('modules.security.scanner.ServerScanner._check_authorized_keys')
    @patch('modules.security.scanner.ServerScanner._check_file_integrity')
    @patch('modules.security.scanner.ServerScanner._check_services')
    @patch('modules.security.scanner.ServerScanner._check_ports')
    @patch('modules.security.scanner.ServerScanner._check_ssh')
    @patch('modules.security.scanner.ServerScanner._check_firewall')
    def test_silent_scan_no_issues(self, mock_fw, mock_ssh, mock_ports, 
                                    mock_svc, mock_fim, mock_keys, mock_pkg):
        """silent scan harus mengembalikan string kosong jika tidak ada masalah"""
        mock_fw.return_value = ["🟢 All good"]
        mock_ssh.return_value = ["🟢 SSH OK"]
        mock_ports.return_value = []
        mock_svc.return_value = ["🟢 Services OK"]
        mock_fim.return_value = ["🟢 FIM OK"]
        mock_keys.return_value = ["🟢 Keys OK"]
        mock_pkg.return_value = ["🟢 Packages OK"]
        
        result = ServerScanner.scan_silent()
        self.assertEqual(result, "")

    @patch('modules.security.scanner.ServerScanner._check_outdated_packages')
    @patch('modules.security.scanner.ServerScanner._check_authorized_keys')
    @patch('modules.security.scanner.ServerScanner._check_file_integrity')
    @patch('modules.security.scanner.ServerScanner._check_services')
    @patch('modules.security.scanner.ServerScanner._check_ports')
    @patch('modules.security.scanner.ServerScanner._check_ssh')
    @patch('modules.security.scanner.ServerScanner._check_firewall')
    def test_silent_scan_with_issues(self, mock_fw, mock_ssh, mock_ports, 
                                      mock_svc, mock_fim, mock_keys, mock_pkg):
        """silent scan harus mengembalikan laporan jika ada masalah 🔴"""
        mock_fw.return_value = ["🔴 UFW Inactive!"]
        mock_ssh.return_value = ["🟢 SSH OK"]
        mock_ports.return_value = []
        mock_svc.return_value = ["🟢 Services OK"]
        mock_fim.return_value = ["🔴 File changed!"]
        mock_keys.return_value = ["🟢 Keys OK"]
        mock_pkg.return_value = ["🟢 Packages OK"]
        
        result = ServerScanner.scan_silent()
        self.assertIn("AUTO-SCAN ALERT", result)
        self.assertIn("2 masalah", result)


if __name__ == '__main__':
    unittest.main()
