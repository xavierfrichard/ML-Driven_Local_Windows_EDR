"""
EMBER v2 (2381-dim) feature extractor — the reference implementation that trains the model and is the
parity target for the C# Warden.Ml.EmberFeatureExtractor.

Byte-only groups (histogram, byteentropy, strings = 616 dims) are implemented to match the C# port
byte-for-byte. PE-parsed groups use LIEF, per docs/phase3-research/ember-v2-spec.md. The hashing trick
uses sklearn's FeatureHasher (which the C# Hashing port reproduces exactly).

Requires: numpy, lief, scikit-learn.
"""
import re
import numpy as np
from sklearn.feature_extraction import FeatureHasher
from sklearn.utils.murmurhash import murmurhash3_bytes_s32

EMBER_DIM = 2381


# ---------- byte-only groups (exact C# parity) ----------

def byte_histogram(data: bytes) -> np.ndarray:
    counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256).astype(np.float32)
    s = counts.sum()
    return counts / s if s > 0 else counts


def _entropy_bin_counts(block: np.ndarray, window: int):
    c = np.bincount(block >> 4, minlength=16)
    p = c.astype(np.float32) / np.float32(window)
    wh = np.where(c)[0]
    H = np.float32(2.0) * np.sum(-p[wh] * np.log2(p[wh]))
    Hbin = int(H * 2)
    if Hbin == 16:
        Hbin = 15
    return Hbin, c


def byte_entropy_histogram(data: bytes, step: int = 1024, window: int = 2048) -> np.ndarray:
    output = np.zeros((16, 16), dtype=np.int64)
    a = np.frombuffer(data, dtype=np.uint8)
    if a.shape[0] < window:
        Hbin, c = _entropy_bin_counts(a, window)
        output[Hbin, :] += c
    else:
        shape = a.shape[:-1] + (a.shape[-1] - window + 1, window)
        strides = a.strides + (a.strides[-1],)
        blocks = np.lib.stride_tricks.as_strided(a, shape=shape, strides=strides)[::step, :]
        for block in blocks:
            Hbin, c = _entropy_bin_counts(block, window)
            output[Hbin, :] += c
    flat = output.flatten().astype(np.float32)
    s = flat.sum()
    return flat / s if s > 0 else flat


def string_features(data: bytes) -> np.ndarray:
    allstrings = re.compile(b'[\x20-\x7f]{5,}').findall(data)
    if allstrings:
        numstrings = len(allstrings)
        avlength = sum(len(s) for s in allstrings) / numstrings
        as_shifted = np.frombuffer(b''.join(allstrings), dtype=np.uint8) - ord(b' ')
        c = np.bincount(as_shifted, minlength=96)
        printables = int(c.sum())
        if printables > 0:
            csum = c.sum()
            p = c.astype(np.float64) / csum
            wh = np.where(c)[0]
            entropy = float(np.sum(-p[wh] * np.log2(p[wh])))
        else:
            entropy = 0.0
    else:
        numstrings, avlength, printables, entropy = 0, 0.0, 0, 0.0
        c = np.zeros(96, dtype=np.int64)

    paths = len(re.compile(b'c:\\\\', re.IGNORECASE).findall(data))
    urls = len(re.compile(b'https?://', re.IGNORECASE).findall(data))
    registry = len(re.compile(b'HKEY_').findall(data))
    mz = len(re.compile(b'MZ').findall(data))

    divisor = float(printables) if printables > 0 else 1.0
    return np.hstack([
        numstrings, avlength, printables,
        c.astype(np.float32) / divisor,
        entropy, paths, urls, registry, mz,
    ]).astype(np.float32)


# ---------- hashing helpers (parity with C# Warden.Ml.Hashing) ----------

def _hash_strings(tokens, n):
    return FeatureHasher(n, input_type="string").transform([list(tokens)]).toarray()[0]


def _hash_pairs(pairs, n):
    return FeatureHasher(n, input_type="pair").transform([list(pairs)]).toarray()[0]


def _hash_chars(s, n):
    # EMBER's transform([entry_string]) iterated the string into characters; replicate explicitly
    # (sklearn 1.9 rejects a bare string sample). Matches C# Hashing.HashCharacters.
    vec = np.zeros(n, dtype=np.float64)
    for ch in s:
        h = murmurhash3_bytes_s32(ch.encode("utf-8"), 0)
        idx = (2147483647 - (n - 1)) % n if h == -2147483648 else abs(h) % n
        vec[idx] += 1.0 if h >= 0 else -1.0
    return vec


# ---------- PE-parsed groups (LIEF) ----------

def _last(token) -> str:
    return str(token).split('.')[-1]


def _parse(data: bytes):
    import lief
    try:
        return lief.PE.parse(list(data))
    except Exception:
        return None


def general_info(data: bytes, b) -> np.ndarray:
    if b is None:
        return np.array([len(data), 0, 0, 0, 0, 0, 0, 0, 0, 0], dtype=np.float32)
    return np.array([
        len(data), b.virtual_size, int(b.has_debug), len(b.exported_functions),
        len(b.imported_functions), int(b.has_relocations), int(b.has_resources),
        int(getattr(b, "has_signatures", getattr(b, "has_signature", 0))),
        int(b.has_tls), len(b.symbols),
    ], dtype=np.float32)


def header_info(b) -> np.ndarray:
    if b is None:
        return np.zeros(62, dtype=np.float32)
    coff, opt = b.header, b.optional_header
    return np.hstack([
        coff.time_date_stamps,
        _hash_strings([_last(coff.machine)], 10),
        _hash_strings([_last(c) for c in coff.characteristics_list], 10),
        _hash_strings([_last(opt.subsystem)], 10),
        _hash_strings([_last(c) for c in opt.dll_characteristics_lists], 10),
        _hash_strings([_last(opt.magic)], 10),
        opt.major_image_version, opt.minor_image_version,
        opt.major_linker_version, opt.minor_linker_version,
        opt.major_operating_system_version, opt.minor_operating_system_version,
        opt.major_subsystem_version, opt.minor_subsystem_version,
        opt.sizeof_code, opt.sizeof_headers, opt.sizeof_heap_commit,
    ]).astype(np.float32)


def section_info(b) -> np.ndarray:
    if b is None or not b.sections:
        return np.zeros(255, dtype=np.float32)
    sections = b.sections
    props = {s.name: [_last(c) for c in s.characteristics_lists] for s in sections}
    entry = ""
    try:
        entry_s = b.section_from_rva(b.optional_header.addressof_entrypoint)
        entry = entry_s.name if entry_s is not None else ""
    except Exception:
        for s in sections:
            if "MEM_EXECUTE" in props[s.name]:
                entry = s.name
                break
    general = [
        len(sections),
        sum(1 for s in sections if s.size == 0),
        sum(1 for s in sections if s.name == ""),
        sum(1 for s in sections if "MEM_READ" in props[s.name] and "MEM_EXECUTE" in props[s.name]),
        sum(1 for s in sections if "MEM_WRITE" in props[s.name]),
    ]
    return np.hstack([
        general,
        _hash_pairs([(s.name, s.size) for s in sections], 50),
        _hash_pairs([(s.name, s.entropy) for s in sections], 50),
        _hash_pairs([(s.name, s.virtual_size) for s in sections], 50),
        _hash_chars(entry, 50),
        _hash_strings([p for s in sections if s.name == entry for p in props[s.name]], 50),
    ]).astype(np.float32)


def imports_info(b) -> np.ndarray:
    if b is None or not b.has_imports:
        return np.zeros(1280, dtype=np.float32)
    raw = {}
    for lib in b.imports:
        raw.setdefault(lib.name, [])
        for e in lib.entries:
            raw[lib.name].append("ordinal" + str(e.ordinal) if e.is_ordinal else e.name[:10000])
    libraries = list(set(l.lower() for l in raw.keys()))
    imports = [l.lower() + ':' + e for l, es in raw.items() for e in es]
    return np.hstack([_hash_strings(libraries, 256), _hash_strings(imports, 1024)]).astype(np.float32)


def exports_info(b) -> np.ndarray:
    if b is None or not b.has_exports:
        return np.zeros(128, dtype=np.float32)
    names = [e.name[:10000] for e in b.get_export().entries]
    return _hash_strings(names, 128).astype(np.float32)


def data_directories(b) -> np.ndarray:
    features = np.zeros(2 * 15, dtype=np.float32)
    if b is None:
        return features
    dirs = list(b.data_directories)
    for i in range(min(15, len(dirs))):
        features[2 * i] = dirs[i].size
        features[2 * i + 1] = dirs[i].rva
    return features


def feature_vector(data: bytes) -> np.ndarray:
    b = _parse(data)
    return np.hstack([
        byte_histogram(data), byte_entropy_histogram(data), string_features(data),
        general_info(data, b), header_info(b), section_info(b),
        imports_info(b), exports_info(b), data_directories(b),
    ]).astype(np.float32)
