from pathlib import Path
import tempfile

import mmdb_writer
import maxminddb
from netaddr import IPSet

IP = "81.2.69.142"
EXPECTED_ASN = 4_200_000_000


with tempfile.TemporaryDirectory() as temp_dir:
    db_path = Path(temp_dir) / "test-asn.mmdb"

    writer = mmdb_writer.MMDBWriter(
        ip_version=6,
        ipv4_compatible=True,
        database_type="GeoLite2-ASN",
        languages=["en"],
        description={"en": "ASN diagnostic database"},
        int_type="u32",
    )

    writer.insert_network(
        IPSet([f"{IP}/32"]),
        {
            "autonomous_system_number": EXPECTED_ASN,
            "autonomous_system_organization": "BIG-PRIVATE-USE-ASN",
        },
    )

    encoder = mmdb_writer.Encoder(int_type="u32", cache=False)
    encoded = encoder.encode(EXPECTED_ASN)

    print("Expected ASN:", EXPECTED_ASN)
    print("Encoder type:", encoder.python_type_id(EXPECTED_ASN))
    print("Encoded bytes:", encoded.hex())
    print(
        "Encoded unsigned value:",
        int.from_bytes(encoded[1:], byteorder="big"),
    )

    writer.to_db_file(str(db_path))
    print("Database size:", db_path.stat().st_size)

    # Check which reader implementations are available.
    print("\nAvailable reader modes:")

    for mode in ("MODE_AUTO", "MODE_FILE", "MODE_MEMORY"):
        reader_mode = getattr(maxminddb, mode, None)
        if reader_mode is None:
            continue

        try:
            with maxminddb.open_database(
                str(db_path),
                mode=reader_mode,
            ) as reader:
                record = reader.get(IP)
                print(f"{mode}: {record}")
        except Exception as exc:
            print(f"{mode} failed: {type(exc).__name__}: {exc}")
