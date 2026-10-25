import io
import stat
import tempfile
import threading
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from xss_audit.importer import GitHubRedirects, extract_archive, import_github, parse_repository


def archive_bytes(files):
    data = io.BytesIO()
    with zipfile.ZipFile(data, 'w', zipfile.ZIP_DEFLATED) as archive:
        for name, content in files:
            info = zipfile.ZipInfo(name)
            info.filename = name  # Keep malicious backslashes in the actual ZIP header on Windows.
            archive.writestr(info, content, compress_type=zipfile.ZIP_DEFLATED)
    return data.getvalue()


class ImportTests(unittest.TestCase):
    def test_repository_allowlist(self):
        self.assertEqual(parse_repository('owner/repo'), ('owner', 'repo'))
        self.assertEqual(parse_repository('https://github.com/owner/repo.git'), ('owner', 'repo'))
        for url in ('https://github.com.evil.example/o/r', 'http://github.com/o/r', 'https://user@github.com/o/r',
                    'https://github.com/o/r/tree/main', 'https://github.com/o/r?x=1', '../repo', 'file:///tmp/repo'):
            with self.assertRaises(ValueError, msg=url):
                parse_repository(url)

    def test_extract_normal_archive(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            archive = base/'source.zip'
            archive.write_bytes(archive_bytes([('owner-repo/中文/example.js', 'el.innerHTML = q;')]))
            target = base/'out'
            target.mkdir()
            root = extract_archive(archive, target)
            self.assertEqual(root.name, 'owner-repo')
            self.assertTrue((root/'中文/example.js').is_file())

    def test_reject_traversal_windows_devices_streams_and_links(self):
        bad_names = ['../outside.js', '/absolute.js', 'root/../../outside.js', 'C:/outside.js',
                     'root/file:stream', 'root/CON.txt', 'root/name.', 'root/name ', 'root\\bad.js']
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            for index, name in enumerate(bad_names):
                target = base/str(index)
                target.mkdir()
                archive = base/f'{index}.zip'
                archive.write_bytes(archive_bytes([(name, 'bad')]))
                with self.assertRaises(ValueError, msg=name):
                    extract_archive(archive, target)
                self.assertFalse(any(target.iterdir()))
            info = zipfile.ZipInfo('root/link')
            info.create_system = 3
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            data = io.BytesIO()
            with zipfile.ZipFile(data, 'w') as archive:
                archive.writestr(info, '/outside')
            archive_path = base/'link.zip'
            archive_path.write_bytes(data.getvalue())
            target = base/'symlink'
            target.mkdir()
            with self.assertRaises(ValueError):
                extract_archive(archive_path, target)

    def test_case_collisions_limits_and_existing_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            archive = base/'source.zip'
            target = base/'out'
            target.mkdir()
            archive.write_bytes(archive_bytes([('root/A.js', 'a'), ('root/a.js', 'b')]))
            with self.assertRaises(ValueError):
                extract_archive(archive, target)
            archive.write_bytes(archive_bytes([('root/a.js', 'x'*100)]))
            with patch('xss_audit.importer.MAX_EXTRACT', 50):
                with self.assertRaises(ValueError):
                    extract_archive(archive, target)
            (target/'keep.txt').write_text('keep')
            with self.assertRaises(ValueError):
                extract_archive(archive, target)
            self.assertEqual((target/'keep.txt').read_text(), 'keep')

    def test_download_snapshot_and_preserve_parent_on_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            marker = parent/'keep.txt'
            marker.write_text('keep')
            raw = archive_bytes([('owner-repo/app.js', 'const x=1;')])
            requests = []
            def transport(request, timeout):
                requests.append(request.full_url)
                return io.BytesIO(raw)
            root, metadata = import_github('owner/repo', 'feature/test', parent, transport=transport)
            self.assertEqual(requests[0], 'https://api.github.com/repos/owner/repo/zipball/feature%2Ftest')
            self.assertTrue((root/'app.js').exists())
            self.assertEqual(len(metadata['archive_sha256']), 64)
            before = set(parent.iterdir())
            with self.assertRaises(ValueError):
                import_github('owner/repo', destination=parent, transport=lambda *a, **k: io.BytesIO(b'not a zip'))
            self.assertEqual(set(parent.iterdir()), before)
            with patch('xss_audit.importer.MAX_DOWNLOAD', 1):
                with self.assertRaises(ValueError):
                    import_github('owner/repo', destination=parent, transport=transport)
            self.assertEqual(set(parent.iterdir()), before)
            self.assertEqual(marker.read_text(), 'keep')

    def test_cancel_and_disallowed_redirect(self):
        with tempfile.TemporaryDirectory() as directory:
            event = threading.Event()
            event.set()
            with self.assertRaises(ValueError):
                import_github('owner/repo', destination=directory, cancel=event,
                              transport=lambda *a, **k: io.BytesIO(archive_bytes([('root/a.js', 'code')])))
            self.assertFalse(any(Path(directory).iterdir()))
        for url in ('https://evil.example/archive.zip', 'http://codeload.github.com/o/r'):
            with self.assertRaises(ValueError):
                GitHubRedirects().redirect_request(None, None, 302, '', {}, url)


if __name__ == '__main__':
    unittest.main()
