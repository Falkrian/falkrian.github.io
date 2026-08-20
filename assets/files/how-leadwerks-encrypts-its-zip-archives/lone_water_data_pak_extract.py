from pathlib import Path
from zipfile import ZipFile

build_mask = bytes.fromhex(
    "22 80 3E 61 22 4B 54 20"
    "54 15 25 08 E3 10 A9 24"
    "16 AE 8A BF A3 34 0A 30"
    "B3 80 DB 8F 62 1C B1 8E"
)

def derive_password(filename: bytes, uncompressed_size: int) -> bytes:
    expanded = bytearray(filename)

    while len(expanded) < 32:
        previous = bytes(expanded)
        expanded += b"\x2D\x39\xC2" + previous

    size_mask = f"{uncompressed_size}. _".encode("ascii")

    password = bytes(
        value
        ^ size_mask[i % len(size_mask)]
        ^ build_mask[i % len(build_mask)]
        for i, value in enumerate(expanded)
    )

    return password.split(b"\x00", 1)[0]

script_directory = Path(__file__).resolve().parent
archive_path = script_directory / "data.pak"
output_path = script_directory / "data_extracted"

with ZipFile(archive_path) as archive:
    for entry in archive.infolist():
        filename = entry.filename.encode("ascii")
        password = derive_password(filename, entry.file_size)

        archive.extract(entry, output_path, pwd=password)
        print(entry.filename)