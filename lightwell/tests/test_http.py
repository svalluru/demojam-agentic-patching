import io
import sys
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scanner import http                                                   # noqa: E402


class FakeResponse:
    def __init__(self, body: bytes, headers=None):
        self._b = io.BytesIO(body)
        self.headers = headers or {}

    def read(self, n=None):
        return self._b.read(n) if n is not None else self._b.read()

    def __enter__(self): return self
    def __exit__(self, *a): return False


class RequestTests(unittest.TestCase):
    def test_json_is_parsed_and_header_names_are_lowercased(self):
        with mock.patch.object(http.urllib.request, 'urlopen', return_value=FakeResponse(b'{"a": 1}', {'X-Next-Page': '2'})):
            body, headers = http.request('t', 'https://x.test/a')
        self.assertEqual((body, headers['x-next-page']), ({'a': 1}, '2'))

    def test_a_raw_download_over_the_cap_is_refused_without_reading_it_all(self):
        resp = FakeResponse(b'x' * 5000)
        with mock.patch.object(http.urllib.request, 'urlopen', return_value=resp):
            with self.assertRaises(http.UpstreamError) as ctx:
                http.request('t', 'https://x.test/big', raw=True, max_bytes=1000)
        self.assertIn('larger than', ctx.exception.message)
        self.assertGreater(resp._b.tell(), 0)
        self.assertLessEqual(resp._b.tell(), 1001)                         # it stopped reading at the cap

    def test_a_raw_download_under_the_cap_is_returned(self):
        with mock.patch.object(http.urllib.request, 'urlopen', return_value=FakeResponse(b'hello')):
            body, _ = http.request('t', 'https://x.test/small', raw=True, max_bytes=1000)
        self.assertEqual(body, b'hello')

    def test_errors_name_the_service_and_never_the_query_string(self):
        err = urllib.error.HTTPError('https://x.test/a?token=SECRET', 404, 'nf', {}, io.BytesIO(b''))
        with mock.patch.object(http.urllib.request, 'urlopen', side_effect=err):
            with self.assertRaises(http.UpstreamError) as ctx:
                http.request('Svc', 'https://x.test/a?token=SECRET')
        self.assertEqual((ctx.exception.service, ctx.exception.status), ('Svc', 404))
        self.assertNotIn('SECRET', str(ctx.exception))


if __name__ == '__main__':
    unittest.main()
