"""Exercise the desktop event loop without injecting input into the user's desktop."""
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import tkinter as tk
from xss_audit.gui import AuditApp
from xss_audit.state import StateStore


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
                app.store = StateStore(base / "state")
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
                app.review_status.set("误报")
                app.review_note.set("人工复核示例")
                app.save_review()
                self.assertTrue(any(item.status == "误报" for item in app.result.matches))
                app.status_filter.set("误报")
                app.refresh()
                self.assertEqual(len(app.tree.get_children()), 1)
                app.status_filter.set("待人工确认")
                app.refresh()
                self.assertFalse(app.tree.get_children())
                self.assertEqual(str(app.review_button.cget("state")), "disabled")
                self.assertEqual(app.review_note.get(), "")
                app.category.set("全部类别")
                app.refresh()
                self.assertTrue(app.tree.get_children())
                app.status_filter.set("全部状态")
                app.refresh()
                app.show_scope()
                self.assertIn('max_file_bytes', app.scope_text.get("1.0", "end"))
                app.search.set("does-not-exist")
                self.assertFalse(app.tree.get_children())
                app.search.set("")
                self.assertTrue(app.tree.get_children())
                for extension in ("json", "md", "html", "sarif"):
                    report = base / ("报告." + extension)
                    with patch("xss_audit.gui.filedialog.asksaveasfilename", return_value=str(report)):
                        app.export()
                    self.assertIn("innerHTML", report.read_text(encoding="utf-8"))
        finally:
            root.destroy()


if __name__ == "__main__":
    unittest.main()
