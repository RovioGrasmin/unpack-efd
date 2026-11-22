#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Распаковщик файлов поставки 1С:Предприятие (.efd) -> .cf / .cfu и доп. файлы.

Реализован НА ЧИСТОЙ СТАНДАРТНОЙ БИБЛИОТЕКЕ Python (zlib, struct, datetime, os).
Внешних зависимостей НЕТ.

Формат EFD (по результатам анализа структуры файла):
  1) Весь файл .efd  -- это поток RAW DEFLATE (zlib без заголовка, wbits = -15).
  2) После распаковки получаем контейнер со структурой (всё little-endian):
       header           : uint32  (== 1, версия формата)
       supply_count     : uint32  (кол-во блоков описания поставки)
       supply_info[]    : по supply_count штук:
                            reserved : 4 байта (назначение неизвестно)
                            строка lang
                            строка supply_name
                            строка provider_name
                            строка description_path
       files_count      : uint32  (кол-во вложенных файлов)
       file_info[]      : по files_count штук:
                            reserved : 4 байта
                            строка filename (путь в стиле Windows, со слэшем '\\')
                            filetime : uint64 (FILETIME: 100-нс интервалы с 1601-01-01)
                            reserved : 4 байта
                            file_size: uint32 (размер файла в байтах)
       <данные файлов>  : подряд, тело каждого файла ровно file_size байт.
  Строка        : uint32 длина_в_символах, затем длина*2 байт в кодировке UTF-16.

Использование:
    python3 unpack_efd.py <файл.efd> <папка-назначения>
"""

import os
import sys
import zlib
import tempfile
from struct import unpack

CHUNK = 10 * 1024 * 1024  # 10 МБ -- размер блока чтения/записи


def read_string(f):
    """Строка 1С: uint32 длина в символах + длина*2 байт UTF-16."""
    char_len = unpack('I', f.read(4))[0]
    return f.read(char_len * 2).decode('utf-16')


def unpack_efd(efd_path, output_dir):
    """Распаковывает .efd в output_dir, сохраняя вложенную структуру каталогов."""
    with open(efd_path, 'rb') as src, tempfile.TemporaryFile() as buf:
        # 1) Потоковая RAW-DEFLATE распаковка всего файла во временный буфер на диске
        decompressor = zlib.decompressobj(-15)
        while True:
            chunk = src.read(CHUNK)
            if not chunk:
                break
            buf.write(decompressor.decompress(chunk))
        buf.write(decompressor.flush())
        buf.seek(0)

        # 2) Заголовок
        header, supply_count = unpack('II', buf.read(8))
        if header != 1:
            raise ValueError('Неизвестный формат EFD (header=%d, ожидался 1)' % header)

        # 3) Пропускаем блоки описания поставки (для извлечения файлов не нужны)
        for _ in range(supply_count):
            buf.read(4)                 # reserved
            for _ in range(4):          # lang, supply_name, provider_name, description_path
                read_string(buf)

        # 4) Каталог вложенных файлов
        files_count = unpack('I', buf.read(4))[0]
        files = []
        for _ in range(files_count):
            buf.read(4)                 # reserved
            filename = read_string(buf)
            buf.read(8)                 # filetime (FILETIME) -- не используется
            buf.read(4)                 # reserved
            file_size = unpack('I', buf.read(4))[0]
            files.append((filename, file_size))

        # 5) Тела файлов идут подряд, ровно по file_size байт
        for filename, file_size in files:
            # путь в EFD всегда в Windows-стиле (обратный слэш)
            rel_parts = filename.split('\\')
            path = os.path.join(os.path.abspath(output_dir), *rel_parts)
            os.makedirs(os.path.dirname(path), exist_ok=True)

            with open(path, 'wb') as out:
                remaining = file_size
                while remaining > 0:
                    data = buf.read(min(CHUNK, remaining))
                    if not data:
                        raise EOFError('Файл оборван при чтении: %s' % filename)
                    out.write(data)
                    remaining -= len(data)
            print('  +', filename)


def main():
    if len(sys.argv) != 3:
        sys.exit('Использование: python3 unpack_efd.py <файл.efd> <папка-назначения>')
    efd_path, output_dir = sys.argv[1], sys.argv[2]
    if not os.path.isfile(efd_path):
        sys.exit('Файл не найден: %s' % efd_path)
    unpack_efd(efd_path, output_dir)
    print('Готово. Распаковано в:', os.path.abspath(output_dir))


if __name__ == '__main__':
    main()
