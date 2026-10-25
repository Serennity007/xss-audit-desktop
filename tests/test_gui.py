"""Exercise the desktop event loop without injecting input into the user's desktop."""
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import tkinter as tk
from xss_audit.gui import AuditApp


class DesktopTests(unittest.TestCase):
    def test_scan_filter_detail_and_export(self):
        try:
            root = tk.Tk()
        except tk.TclError:
            self.skipTest("Tk display not available")
        root.withdraw()
        try:
            app = AuditApp(root)
            with tempfile.TemporaryDirectory() as directory:
                base = Path(directory)
                code = base / "中文代码"
                code.mkdir()
                (code / "example.js").write_text("const input = location.search;\nel.innerHTML = input;\nwindow.open(input);", encoding="utf-8")
                app.path.set(str(code))
                with patch("xss_audit.gui.messagebox.showerror") as error:
                    app.start_scan()
                    deadline = time.monotonic() + 8
                    while app.busy and time.monotonic() < deadline:
                        root.update()
                        time.sleep(.01)
                    self.assertFalse(app.busy, "Desktop worker did not complete")
                    error.assert_not_called()
                self.assertEqual(app.result.files_scanned, 1)
                self.assertGreaterEqual(len(app.tree.get_children()), 2)
                app.category.set("1. DOM / HTML 注入")
                app.refresh()
                rows = app.tree.get_children()
                self.assertEqual(len(rows), 1)
                app.tree.selection_set(rows[0])
                app.show_match()
                self.assertIn("innerHTML", app.detail.get("1.0", "end"))
                for extension in ("json", "md"):
                    report = base / ("报告." + extension)
                    with patch("xss_audit.gui.filedialog.asksaveasfilename", return_value=str(report)):
                        app.export()
                    self.assertIn("innerHTML", report.read_text(encoding="utf-8"))
        finally:
            root.destroy()


if __name__ == "__main__":
    unittest.main()
