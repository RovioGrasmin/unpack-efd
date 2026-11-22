#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Никита Шварев
"""
unpack_efd.py v1.1 — распаковка поставок и обновлений 1С (.efd) в .cf / .cfu.

Только стандартная библиотека CPython: нет сети, нет subprocess, нет root.
Запускается на том интерпретаторе, который уже есть в системе.

Формат (по результатам разбора, сверено с независимой реализацией):
  1) Весь файл .efd - поток RAW DEFLATE (zlib без заголовка, wbits = -15).
  2) После распаковки - контейнер, всё little-endian:
       header          : uint32  (== 1, версия формата)
       supply_count    : uint32
       supply_info[]   : по supply_count штук: 4 байта + 4 строки
                         (lang, supply_name, provider_name, description_path)
       files_count     : uint32
       file_info[]     : по files_count штук: 4 байта, имя, uint64 FILETIME,
                         4 байта, uint32 размер
       <данные файлов> : тела подряд, ровно по file_size байт
  Строка: uint32 длина в символах, затем длина*2 байт в UTF-16.

Использование:
    python3 unpack_efd.py <файл.efd> <папка>
    python3 unpack_efd.py --list <файл.efd>
    python3 unpack_efd.py --sha256 <hex> <файл.efd> <папка>

Коды возврата:
    0 - успех
    1 - ошибка ввода-вывода или аргументов
    2 - файл не является корректным .efd
    3 - превышен защитный предел разбора
"""

from __future__ import annotations

import argparse
import hashlib
import os
import sys
import tempfile
import zlib
from datetime import datetime, timedelta
from struct import unpack

__version__ = "1.1"

CHUNK = 10 * 1024 * 1024            # блок чтения/записи
FILETIME_EPOCH = datetime(1601, 1, 1)

# Защитные пределы разбора: отсекают заведомо битый или враждебный файл
# до того, как он заставит выделять память или писать вне каталога вывода.
MAX_STRING_CHARS = 4096             # длина любого поля-строки
MAX_SUPPLY_ENTRIES = 64             # блоков описания поставки
MAX_FILE_ENTRIES = 100000           # записей в оглавлении
MAX_TOTAL_SIZE = 64 << 30           # суммарный объём поставки, 64 ГиБ

EXIT_OK = 0
EXIT_IO = 1
EXIT_FORMAT = 2
EXIT_LIMIT = 3


class FormatError(Exception):
    """Файл повреждён или не является .efd."""


class LimitError(Exception):
    """Разбор упёрся в защитный предел."""


def read_string(stream):
    """Строка 1С: uint32 длина в символах + длина*2 байт UTF-16."""
    raw = stream.read(4)
    if len(raw) != 4:
        raise FormatError("обрыв потока на заголовке строки")
    char_len = unpack("I", raw)[0]
    if char_len > MAX_STRING_CHARS:
        raise LimitError(
            "длина строки %d превышает предел %d" % (char_len, MAX_STRING_CHARS)
        )
    data = stream.read(char_len * 2)
    if len(data) != char_len * 2:
        raise FormatError("обрыв потока на теле строки")
    return data.decode("utf-16", errors="strict")


def safe_rel_parts(name):
    """
    Разбирает путь из контейнера в список безопасных сегментов.

    Отбрасывает всё, что может вывести запись за каталог назначения:
    пустые сегменты, '.', '..', абсолютные пути и буквы диска.
    """
    if not name:
        raise FormatError("пустое имя файла в оглавлении")
    normalised = name.replace("/", "\\")
    parts = []
    for segment in normalised.split("\\"):
        if segment in ("", ".", ".."):
            raise FormatError("недопустимый сегмент пути: %r" % name)
        if os.path.isabs(segment) or ":" in segment:
            raise FormatError("абсолютный путь или диск в имени: %r" % name)
        parts.append(segment)
    return parts


def parse_catalog(stream):
    """Читает оглавление из распакованного потока. Возвращает (описания, файлы, объём)."""
    head = stream.read(8)
    if len(head) != 8:
        raise FormatError("файл короче заголовка контейнера")
    header, supply_count = unpack("II", head)
    if header != 1:
        raise FormatError("неизвестный формат EFD (header=%d, ожидался 1)" % header)
    if supply_count > MAX_SUPPLY_ENTRIES:
        raise LimitError(
            "блоков описания %d больше предела %d"
            % (supply_count, MAX_SUPPLY_ENTRIES)
        )

    supplies = []
    for _ in range(supply_count):
        stream.read(4)                                  # reserved
        supplies.append(
            (
                read_string(stream),                    # lang
                read_string(stream),                    # supply_name
                read_string(stream),                    # provider_name
                read_string(stream),                    # description_path
            )
        )

    raw_count = stream.read(4)
    if len(raw_count) != 4:
        raise FormatError("обрыв потока перед оглавлением файлов")
    files_count = unpack("I", raw_count)[0]
    if files_count > MAX_FILE_ENTRIES:
        raise LimitError(
            "записей в оглавлении %d больше предела %d"
            % (files_count, MAX_FILE_ENTRIES)
        )

    files = []
    total = 0
    for _ in range(files_count):
        stream.read(4)                                  # reserved
        name = read_string(stream)
        filetime = unpack("Q", stream.read(8))[0]
        stream.read(4)                                  # reserved
        raw_size = stream.read(4)
        if len(raw_size) != 4:
            raise FormatError("обрыв потока в записи оглавления")
        size = unpack("I", raw_size)[0]
        total += size
        if total > MAX_TOTAL_SIZE:
            raise LimitError(
                "суммарный объём поставки превышает предел %d байт" % MAX_TOTAL_SIZE
            )
        files.append((safe_rel_parts(name), name, filetime, size))
    return supplies, files, total


def filetime_to_datetime(filetime):
    """FILETIME (100-нс от 1601-01-01) в datetime."""
    if not filetime:
        return None
    try:
        return FILETIME_EPOCH + timedelta(microseconds=filetime / 10)
    except (OverflowError, ValueError):
        return None


def sha256_of(path):
    """SHA-256 файла, потоково."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while True:
            chunk = handle.read(CHUNK)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def decompress_to(efd_path, buffer):
    """
    Распаковывает RAW DEFLATE поток в переданный файловый объект.

    Возвращает True, если после конца deflate-потока остались лишние байты.
    """
    decompressor = zlib.decompressobj(-15)
    with open(efd_path, "rb") as src:
        while True:
            chunk = src.read(CHUNK)
            if not chunk:
                break
            buffer.write(decompressor.decompress(chunk))
    buffer.write(decompressor.flush())
    return bool(decompressor.unused_data)


def human(size):
    """Размер в удобочитаемом виде."""
    value = float(size)
    for unit in ("Б", "КБ", "МБ", "ГБ"):
        if value < 1024 or unit == "ГБ":
            if unit == "Б":
                return "%d Б" % size
            return "%.1f %s" % (value, unit)
        value /= 1024.0
    return "%d Б" % size


def build_parser():
    parser = argparse.ArgumentParser(
        prog="unpack_efd.py",
        description="Распаковка поставок и обновлений 1С (.efd). Только stdlib.",
    )
    parser.add_argument("efd", help="путь к файлу .efd")
    parser.add_argument(
        "output", nargs="?", help="каталог для распаковки (не нужен с --list)"
    )
    parser.add_argument(
        "--list", action="store_true", dest="list_only",
        help="показать оглавление, не распаковывая файлы",
    )
    parser.add_argument(
        "--sha256", metavar="HEX",
        help="ожидаемая SHA-256 входного файла; при несовпадении выход с кодом 2",
    )
    parser.add_argument(
        "--tmp", metavar="DIR",
        help="каталог для временного буфера (по умолчанию системный TMPDIR)",
    )
    parser.add_argument(
        "--no-mtime", action="store_true",
        help="не восстанавливать время изменения файлов из FILETIME",
    )
    parser.add_argument(
        "--version", action="version", version="%(prog)s " + __version__
    )
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.list_only and not args.output:
        parser.error("укажите каталог распаковки или используйте --list")

    if not os.path.isfile(args.efd):
        print("Ошибка: файл не найден: %s" % args.efd, file=sys.stderr)
        return EXIT_IO

    if args.sha256:
        expected = args.sha256.strip().lower()
        if expected.startswith("sha256:"):
            expected = expected[len("sha256:"):]
        actual = sha256_of(args.efd)
        if actual != expected:
            print(
                "Ошибка: SHA-256 не совпадает\n  ожидалось: %s\n  получено:  %s"
                % (expected, actual),
                file=sys.stderr,
            )
            return EXIT_FORMAT

    tmp_dir = args.tmp or None
    if tmp_dir and not os.path.isdir(tmp_dir):
        print("Ошибка: каталог для --tmp не существует: %s" % tmp_dir, file=sys.stderr)
        return EXIT_IO

    try:
        with tempfile.TemporaryFile(dir=tmp_dir) as buffer:
            trailing = decompress_to(args.efd, buffer)
            if trailing:
                print(
                    "Предупреждение: после конца deflate-потока остались лишние данные",
                    file=sys.stderr,
                )
            buffer.seek(0)
            supplies, files, total = parse_catalog(buffer)

            if args.list_only:
                for lang, supply_name, provider, _desc in supplies:
                    print("Поставка : %s" % (supply_name or "-"))
                    print("Поставщик: %s" % (provider or "-"))
                    print("Язык     : %s" % (lang or "-"))
                print("Файлов   : %d, объём: %s" % (len(files), human(total)))
                for parts, _name, filetime, size in files:
                    stamp = filetime_to_datetime(filetime)
                    when = stamp.strftime("%Y-%m-%d %H:%M") if stamp else "-"
                    print("  %-12s %s  %s" % (human(size), when, "\\".join(parts)))
                return EXIT_OK

            out_root = os.path.abspath(args.output)
            os.makedirs(out_root, exist_ok=True)

            for parts, name, filetime, size in files:
                target = os.path.join(out_root, *parts)
                parent = os.path.dirname(target)
                if parent:
                    os.makedirs(parent, exist_ok=True)
                remaining = size
                with open(target, "wb") as out:
                    while remaining > 0:
                        data = buffer.read(min(CHUNK, remaining))
                        if not data:
                            raise FormatError("файл оборван при чтении: %s" % name)
                        out.write(data)
                        remaining -= len(data)
                if not args.no_mtime:
                    stamp = filetime_to_datetime(filetime)
                    if stamp:
                        try:
                            ticks = (stamp - datetime(1970, 1, 1)).total_seconds()
                            os.utime(target, (ticks, ticks))
                        except (OverflowError, OSError, ValueError):
                            pass

            print("Распаковано файлов: %d, объём: %s" % (len(files), human(total)))
            print("Каталог: %s" % out_root)
            return EXIT_OK

    except LimitError as error:
        print("Ошибка предела разбора: %s" % error, file=sys.stderr)
        return EXIT_LIMIT
    except FormatError as error:
        print("Ошибка формата: %s" % error, file=sys.stderr)
        return EXIT_FORMAT
    except zlib.error as error:
        print(
            "Ошибка распаковки (повреждён поток deflate): %s" % error,
            file=sys.stderr,
        )
        return EXIT_FORMAT
    except OSError as error:
        print("Ошибка ввода-вывода: %s" % error, file=sys.stderr)
        return EXIT_IO


if __name__ == "__main__":
    sys.exit(main())
