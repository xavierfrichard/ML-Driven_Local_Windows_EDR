"""
Generates the byte-group parity fixtures consumed by the C# EmberByteParityTests. For a set of
DETERMINISTIC byte buffers, dumps the golden histogram (256), byteentropy (256), and strings (104)
vectors produced by the Python reference. The C# test recomputes them and asserts equality.

Run:  python ml-training/gen_byte_parity.py
"""
import json
import os
import numpy as np

import ember_features as ef

OUT = os.path.join(os.path.dirname(__file__), "..", "tests", "Warden.Tests", "parity", "byte_groups.json")


def buffers():
    rng = np.random.RandomState(1234)  # deterministic
    yield "empty", b""
    yield "short_text", b"Hello, World! This is a short test string for Warden."
    yield "paths_urls_reg", (b"open c:\\windows\\system32 and C:\\Users then http://a.test "
                             b"and HTTPS://B.test plus HKEY_LOCAL_MACHINE\\Software MZ MZ header")
    yield "repeated", b"A" * 5000 + b"\x00" * 3000 + bytes(range(256)) * 20
    yield "random_small", rng.randint(0, 256, size=900, dtype=np.uint8).tobytes()
    yield "random_large", rng.randint(0, 256, size=9000, dtype=np.uint8).tobytes()
    yield "mixed", (b"MZ" + b"\x90" * 100 + b"kernel32.dll\x00CreateFileW\x00" * 30
                    + rng.randint(0, 256, size=4000, dtype=np.uint8).tobytes())


def main():
    fixtures = []
    for name, data in buffers():
        fixtures.append({
            "name": name,
            "hex": data.hex(),
            "histogram": ef.byte_histogram(data).astype(float).tolist(),
            "byteentropy": ef.byte_entropy_histogram(data).astype(float).tolist(),
            "strings": ef.string_features(data).astype(float).tolist(),
        })
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(os.path.normpath(OUT), "w", encoding="utf-8") as f:
        json.dump({"fixtures": fixtures}, f)
    print(f"wrote {len(fixtures)} fixtures to {os.path.normpath(OUT)}")


if __name__ == "__main__":
    main()
