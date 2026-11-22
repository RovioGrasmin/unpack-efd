#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: MIT
"""
Тесты unpack_efd.py.

Фикстуры строятся в памяти по описанию формата: в репозитории нет
бинарных .efd, и это сознательно - тесты не зависят от чужих дистрибутивов.

Запуск:
    python3 -m unittest discover -s tests -v
"""

import hashlib
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
import zlib
from datetime import datetime

SCRIPT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                      "unpack_efd.py")

FILE_TIME = 133000000000000000  # 2022-06-18, произвольная валидная метка


def pack_string(text):
    """Строка в формате контейнера: uint32 длина в символах + UTF-16LE."""
    return struct.pack("I", len(text)) + text.encode("utf-16-le")


def build_efd(files, header=1, supply=(("ru", "Supply 1.0", "Vendor", "readme.htm"),)):
    """Собирает валидный контейнер и сжимает его raw-deflate."""
    container = struct.pack("II", header, len(supply))
    for lang, name, provider, description in supply:
        container += b"\0" * 4
        container += pack_string(lang)
        container += pack_string(name)
        container += pack_string(provider)
        container += pack_string(description)
    container += struct.pack("I", len(files))
    for name, data in files:
        container += b"\0" * 4
        container += pack_string(name)
        container += struct.pack("Q", FILE_TIME)
        container += b"\0" * 4
        container += struct.pack("I", len(data))
    for _, data in files:
        container += data
    compressor = zlib.compressobj(9, zlib.DEFLATED, -15)
    return compressor.compress(container) + compressor.flush()


class UnpackEfdTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.files = [("1cv8.cf", b"CONFIGDATA" * 100),
                      ("doc\\readme.htm", b"<html>hi</html>")]
        self.efd = self.write("ok.efd", build_efd(self.files))

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def write(self, name, data):
        path = os.path.join(self.tmp, name)
        with open(path, "wb") as handle:
            handle.write(data)
        return path

    def call(self, *args):
        return subprocess.run([sys.executable, SCRIPT] + list(args),
                              capture_output=True)

    def test_exit_zero_on_valid_file(self):
        self.assertEqual(self.call("--list", self.efd).returncode, 0)

    def test_extracts_content(self):
        out = os.path.join(self.tmp, "out")
        self.assertEqual(self.call(self.efd, out).returncode, 0)
        with open(os.path.join(out, "1cv8.cf"), "rb") as handle:
            self.assertEqual(handle.read(), self.files[0][1])
        with open(os.path.join(out, "doc", "readme.htm"), "rb") as handle:
            self.assertEqual(handle.read(), self.files[1][1])

    def test_restores_mtime(self):
        out = os.path.join(self.tmp, "out_mtime")
        self.assertEqual(self.call(self.efd, out).returncode, 0)
        stamp = datetime.fromtimestamp(os.path.getmtime(os.path.join(out, "1cv8.cf")))
        self.assertEqual(stamp.year, 2022)

    def test_no_mtime_flag(self):
        out = os.path.join(self.tmp, "out_nomtime")
        self.assertEqual(self.call("--no-mtime", self.efd, out).returncode, 0)
        stamp = datetime.fromtimestamp(os.path.getmtime(os.path.join(out, "1cv8.cf")))
        self.assertNotEqual(stamp.year, 2022)

    def test_rejects_unknown_header(self):
        path = self.write("h2.efd", build_efd(self.files, header=2))
        self.assertEqual(self.call("--list", path).returncode, 2)

    def test_rejects_path_traversal(self):
        path = self.write("trav.efd", build_efd([("..\\..\\evil.txt", b"x")]))
        self.assertEqual(self.call("--list", path).returncode, 2)

    def test_rejects_absolute_path(self):
        path = self.write("abs.efd", build_efd([("C:\\Windows\\evil.txt", b"x")]))
        self.assertEqual(self.call("--list", path).returncode, 2)

    def test_rejects_garbage(self):
        path = self.write("garbage.efd", b"\x00\x01\x02\x03not a deflate stream")
        self.assertEqual(self.call("--list", path).returncode, 2)

    def test_missing_file_exit_code(self):
        self.assertEqual(self.call("--list", os.path.join(self.tmp, "nope.efd")).returncode, 1)

    def test_sha256_match(self):
        with open(self.efd, "rb") as handle:
            digest = hashlib.sha256(handle.read()).hexdigest()
        self.assertEqual(self.call("--sha256", digest, "--list", self.efd).returncode, 0)

    def test_sha256_mismatch(self):
        self.assertEqual(self.call("--sha256", "0" * 64, "--list", self.efd).returncode, 2)


if __name__ == "__main__":
    unittest.main()
