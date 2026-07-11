All source retrieved and the FeatureHasher internals confirmed. Here is the exhaustive, implementable spec.

---

# EMBER v2 PE Feature Vector — Exact Spec (byte-for-byte)

**Source of truth:** `elastic/ember`, file `ember/features.py` (MIT). Raw: `https://raw.githubusercontent.com/elastic/ember/master/ember/features.py`. The extractor is `PEFeatureExtractor(feature_version=2)`. Total dim = **2381**. All feature-type subclasses inherit `FeatureType`, expose `name`, `dim`, `raw_features(bytez, lief_binary)` (JSON-able dict/list) and `process_raw_features(raw_obj)` (float32 vector). `feature_vector = process_raw_features(raw_features(...))`.

Two-stage design matters for parity: `raw_features` is LIEF-derived JSON (stored to JSONL during dataset vectorization); `process_raw_features` is pure numpy math. To match byte-for-byte your C# must reproduce **both** LIEF's parsed values **and** the numpy math.

## Concatenation order and dims (version 2)

`np.hstack` of, in this exact order (`PEFeatureExtractor.__init__` inserts them in dict order, then appends `DataDirectories` for v2):

| # | class | name | dim | cumulative offset |
|---|-------|------|-----|--------|
| 1 | ByteHistogram | `histogram` | 256 | 0..255 |
| 2 | ByteEntropyHistogram | `byteentropy` | 256 | 256..511 |
| 3 | StringExtractor | `strings` | 104 | 512..615 |
| 4 | GeneralFileInfo | `general` | 10 | 616..625 |
| 5 | HeaderFileInfo | `header` | 62 | 626..687 |
| 6 | SectionInfo | `section` | 255 | 688..942 |
| 7 | ImportsInfo | `imports` | 1280 | 943..2222 |
| 8 | ExportsInfo | `exports` | 128 | 2223..2350 |
| 9 | DataDirectories | `datadirectories` | 30 | 2351..2380 |

256+256+104+10+62+255+1280+128+30 = **2381**. Final cast: `np.hstack(...).astype(np.float32)` at the top level, and each group is itself already `.astype(np.float32)`.

`feature_version==1` omits `DataDirectories` (dim 2351) and expects LIEF 0.8.3; `==2` appends it and expects LIEF 0.9.0. Anything else raises. Default is **2**.

---

## The FeatureHasher — THE load-bearing parity risk

`sklearn.feature_extraction.FeatureHasher(N, input_type=...)`. Confirmed from sklearn `_hashing_fast.pyx`. Per token:

```
h = murmurhash3_bytes_s32(token.encode('utf-8'), seed=0)   # MurmurHash3 x86_32, SIGNED 32-bit
if h == -2147483648:                                        # INT_MIN special case
    index = (2147483647 - (N - 1)) % N
else:
    index = abs(h) % N
if alternate_sign:            # default True
    value *= (h >= 0) * 2 - 1 # +value if h>=0 else -value
# accumulate: vec[index] += value   (collisions are SUMMED, not deduped)
```

Non-negotiable details:
- **Hash = MurmurHash3 x86 32-bit, seed 0, interpreted as a signed int32.** You must port MurmurHash3_x86_32 exactly (Austin Appleby reference) and reproduce the signed reinterpretation.
- Token bytes are the **UTF-8 encoding** of the string.
- `alternate_sign=True` is the default and EMBER never overrides it → every bucket carries the +1/-1 sign of the hash. Get the sign wrong and every hashed sub-vector is wrong.
- `input_type="string"`: each token contributes **value = 1.0**.
- `input_type="pair"`: each `(name, val)` contributes **value = val** (a float/int), hashing `name`.
- Collisions **sum** (with sign) into the same index. Order of summation is float-associative but sklearn accumulates in a sparse COO then sums duplicates; for float32 targets after cast this is stable in practice, but accumulate in float64 then cast to float32 to match numpy.
- sklearn's `.toarray()[0]` is **float64**; EMBER casts the whole group to float32 afterward. Do your accumulation in double, cast to float32 at the group boundary.

`transform([X])` is always called with a **single sample** (`[...]`), so `.toarray()[0]` is that one row. Watch the string-vs-list nuance below (SectionInfo entry name).

---

## 1. ByteHistogram (256) — `histogram`

```python
def raw_features(self, bytez, lief_binary):
    counts = np.bincount(np.frombuffer(bytez, dtype=np.uint8), minlength=256)
    return counts.tolist()
def process_raw_features(self, raw_obj):
    counts = np.array(raw_obj, dtype=np.float32)
    sum = counts.sum()
    normalized = counts / sum
    return normalized
```

- Count of every byte value 0..255 over the **entire file**. Normalize by total byte count (`sum` = file length). L1-normalized histogram. (Empty file → divide by 0; real PEs are non-empty.)

## 2. ByteEntropyHistogram (256) — `byteentropy`

Params: `step=1024`, `window=2048`. Output is a 16×16 int matrix `output[Hbin, nibble]`, flattened row-major to 256, then L1-normalized.

```python
def _entropy_bin_counts(self, block):
    c = np.bincount(block >> 4, minlength=16)          # high-nibble histogram, 16 bins
    p = c.astype(np.float32) / self.window             # NB: always /2048, even for short blocks
    wh = np.where(c)[0]
    H = np.sum(-p[wh] * np.log2(p[wh])) * 2             # x2: 4-bit reduction correction
    Hbin = int(H * 2)                                   # 0..16
    if Hbin == 16: Hbin = 15                            # clamp entropy==8.0
    return Hbin, c

def raw_features(self, bytez, lief_binary):
    output = np.zeros((16, 16), dtype=np.int)
    a = np.frombuffer(bytez, dtype=np.uint8)
    if a.shape[0] < self.window:
        Hbin, c = self._entropy_bin_counts(a)
        output[Hbin, :] += c
    else:
        shape = a.shape[:-1] + (a.shape[-1] - self.window + 1, self.window)
        strides = a.strides + (a.strides[-1],)
        blocks = np.lib.stride_tricks.as_strided(a, shape=shape, strides=strides)[::self.step, :]
        for block in blocks:
            Hbin, c = self._entropy_bin_counts(block)
            output[Hbin, :] += c
    return output.flatten().tolist()
# process: same normalize-by-sum as ByteHistogram
```

Exact algorithm to replicate:
- Sliding window of **2048** bytes, **step 1024**. Windows are `a[0:2048], a[1024:3072], ...`; the last window starts at the largest `k*1024` with `k*1024 + 2048 <= len`. (Strided view length is `len-window+1`, taken `[::1024]`.) Any trailing bytes that don't fill a full 2048 window are **dropped**.
- Per window: bin high nibble `byte >> 4` into 16 bins → counts `c`.
- `p = c / 2048.0` (note: divides by `window` constant, **not** by the block length — matters only in the `< window` short-file branch where the file is shorter than 2048 but you still divide by 2048).
- `H = 2 * Σ(-p·log2 p)` over nonzero bins (log base 2, natural-log-of-2 division).
- `Hbin = int(H*2)` (truncate toward zero), clamp `16→15`. Row index.
- `output[Hbin] += c` — accumulate the **raw nibble counts** `c` into row `Hbin`.
- Flatten row-major (entropy-bin outer, nibble inner), normalize by total sum. `int()` truncation and float32 intermediate `p` must match.

## 3. StringExtractor (104) — `strings`

`dim = 1 + 1 + 1 + 96 + 1 + 1 + 1 + 1 + 1`. Regexes (operate on **raw bytes**):

```python
self._allstrings = re.compile(b'[\x20-\x7f]{5,}')   # runs of printable ASCII, length >= 5
self._paths      = re.compile(b'c:\\\\', re.IGNORECASE)  # literal  c:\   case-insensitive
self._urls       = re.compile(b'https?://', re.IGNORECASE)
self._registry   = re.compile(b'HKEY_')             # case-SENSITIVE
self._mz         = re.compile(b'MZ')                # case-sensitive
```

`raw_features`:
- `numstrings = len(allstrings)`
- `avlength = sum(len(s))/len(allstrings)` (mean string length; 0 if none)
- Concatenate all matched strings, map each byte `b → b - 0x20` giving 0..95, `c = bincount(minlength=96)` (histogram over the 96 printable codes). Stored **non-normalized** as `printabledist`.
- `printables = int(c.sum())` (total printable chars across all strings)
- `entropy = Σ(-p·log2 p)`, `p = c/csum` over nonzero bins (**no** ×2 here)
- `paths/urls/registry/MZ = len(findall(...))`

`process_raw_features` hstack order (exactly 104):

```python
hist_divisor = float(raw_obj['printables']) if raw_obj['printables'] > 0 else 1.0
np.hstack([
  raw_obj['numstrings'],              # [0]
  raw_obj['avlength'],                # [1]
  raw_obj['printables'],              # [2]  (raw count, NOT normalized)
  np.asarray(raw_obj['printabledist']) / hist_divisor,   # [3:99]  96 dims, divided by printables
  raw_obj['entropy'],                 # [99]
  raw_obj['paths'],                   # [100]
  raw_obj['urls'],                    # [101]
  raw_obj['registry'],                # [102]
  raw_obj['MZ'],                      # [103]
]).astype(np.float32)
```

Note `printables` appears twice: once raw at index 2, and again as the divisor of the 96-bin distribution.

## 4. GeneralFileInfo (10) — `general`

hstack/`np.asarray` order, all scalars, float32:

```
[0] size            = len(bytez)
[1] vsize           = lief_binary.virtual_size
[2] has_debug       = int(lief_binary.has_debug)
[3] exports         = len(lief_binary.exported_functions)
[4] imports         = len(lief_binary.imported_functions)
[5] has_relocations = int(lief_binary.has_relocations)
[6] has_resources   = int(lief_binary.has_resources)
[7] has_signature   = int(lief_binary.has_signatures)   # or has_signature on older LIEF
[8] has_tls         = int(lief_binary.has_tls)
[9] symbols         = len(lief_binary.symbols)
```

If `lief_binary is None`, all fields 0 except `size`.

## 5. HeaderFileInfo (62) — `header`

Enum strings are `str(enum).split('.')[-1]` — the **last dotted component of LIEF's repr** (e.g. `MACHINE_TYPES.AMD64 → "AMD64"`, `HEADER_CHARACTERISTICS.EXECUTABLE_IMAGE → "EXECUTABLE_IMAGE"`). Your C# must emit the **identical token strings LIEF produces** for machine, characteristics, subsystem, dll_characteristics, magic — the hash depends on exact spelling.

`process_raw_features` hstack (62):

```
[0]        coff.timestamp = header.time_date_stamps   (raw int)
[1:11]     FeatureHasher(10,"string").transform([[ coff.machine ]])            # single-token list
[11:21]    FeatureHasher(10,"string").transform([  coff.characteristics ])     # list of char-flags
[21:31]    FeatureHasher(10,"string").transform([[ optional.subsystem ]])
[31:41]    FeatureHasher(10,"string").transform([  optional.dll_characteristics ])
[41:51]    FeatureHasher(10,"string").transform([[ optional.magic ]])
[51] major_image_version
[52] minor_image_version
[53] major_linker_version
[54] minor_linker_version
[55] major_operating_system_version
[56] minor_operating_system_version
[57] major_subsystem_version
[58] minor_subsystem_version
[59] sizeof_code
[60] sizeof_headers
[61] sizeof_heap_commit
```

Each `FeatureHasher(10,...)` is signed-hashed (see algorithm above). `machine/subsystem/magic` are single-element lists `[[x]]`; `characteristics/dll_characteristics` are lists of flag strings.

## 6. SectionInfo (255) — `section`

`dim = 5 + 50 + 50 + 50 + 50 + 50`. Section props: `_properties(s) = [str(c).split('.')[-1] for c in s.characteristics_lists]` (e.g. `"MEM_READ"`, `"MEM_EXECUTE"`, `"MEM_WRITE"`, `"CNT_CODE"`, ...).

`raw_features` builds `{"entry": <entry_section_name>, "sections": [{name,size,entropy,vsize,props}, ...]}`. Entry-section resolution: LIEF ≥0.12 uses `section_from_rva(entrypoint - imagebase)`; else `section_from_offset(entrypoint)`; on `not_found`, first section with `MEM_EXECUTE`, else `""`.

`process_raw_features` (255), hstack order:

```python
general = [
  len(sections),                                                 # [0]
  sum(1 for s in sections if s['size'] == 0),                    # [1]
  sum(1 for s in sections if s['name'] == ""),                   # [2]
  sum(1 for s in sections if 'MEM_READ' in s['props'] and 'MEM_EXECUTE' in s['props']),  # [3]
  sum(1 for s in sections if 'MEM_WRITE' in s['props'])          # [4]
]
# [5:55]   section_sizes   = [(name, size)]     -> FeatureHasher(50,"pair")
# [55:105] section_entropy = [(name, entropy)]  -> FeatureHasher(50,"pair")
# [105:155]section_vsize   = [(name, vsize)]    -> FeatureHasher(50,"pair")
# [155:205]entry_name_hashed = FeatureHasher(50,"string").transform([ raw_obj['entry'] ])
# [205:255]characteristics = [p for s in sections for p in s['props'] if s['name']==raw_obj['entry']]
#          characteristics_hashed = FeatureHasher(50,"string").transform([ characteristics ])
```

Two critical nuances:
- **`entry_name_hashed`: `transform([raw_obj['entry']])` passes the entry name STRING as the single sample.** With `input_type="string"`, iterating a string yields its **characters** — so the entry name is hashed **one character at a time** (each char is a token, value 1, signed, summed). This is an EMBER quirk you must reproduce exactly (do not hash the whole name as one token).
- **Pair values are the raw floats**: `size`/`vsize` are ints, `entropy` is LIEF's section Shannon entropy (a double). The entropy value is summed with sign into its hashed bucket → you must reproduce **LIEF's section-entropy computation bit-for-bit** (Shannon entropy over the section's raw bytes; LIEF's exact byte-frequency + log2 implementation). This and the enum spellings are the section group's parity landmines.

## 7. ImportsInfo (1280) — `imports`

`raw_features` → dict `{libname: [entry, ...]}`. Ordinal entries become `"ordinal" + str(entry.ordinal)`; named entries `entry.name[:10000]` (clip to 10000 chars).

```python
libraries = list(set([l.lower() for l in raw_obj.keys()]))         # dedup, lowercased lib names
libraries_hashed = FeatureHasher(256,"string").transform([libraries]).toarray()[0]   # [0:256]

imports = [lib.lower() + ':' + e for lib, elist in raw_obj.items() for e in elist]
imports_hashed = FeatureHasher(1024,"string").transform([imports]).toarray()[0]      # [256:1280]
np.hstack([libraries_hashed, imports_hashed]).astype(np.float32)
```

Exact token forms:
- Library sub-vector (256): unique **lowercased** library names (`set` dedup — order irrelevant since hashing is order-independent and collisions sum).
- Import pair sub-vector (1024): token = **`lib.lower() + ':' + e`**. The library part is lowercased; the **function name `e` is NOT lowercased**. Example: `"kernel32.dll:CreateFileW"`, `"advapi32.dll:ordinal72"`. Duplicates across libs are kept (not deduped) and their signed contributions sum.

## 8. ExportsInfo (128) — `exports`

`raw_features` → list of exported function name strings, each clipped `[:10000]` (LIEF ≥0.10 uses `export.name`, older uses the string directly).

```python
exports_hashed = FeatureHasher(128,"string").transform([raw_obj]).toarray()[0]
return exports_hashed.astype(np.float32)
```

Tokens are the export name strings, **not lowercased**, hashed as a single sample (the list). 128 dims.

## 9. DataDirectories (30) — `datadirectories` (v2 only)

`dim = 15 * 2`. `raw_features` → list (in LIEF `data_directories` order) of `{name, size, virtual_address(=rva)}`.

```python
features = np.zeros(2 * 15, dtype=np.float32)   # _name_order has 15 entries
for i in range(15):
    if i < len(raw_obj):
        features[2*i]   = raw_obj[i]["size"]
        features[2*i+1] = raw_obj[i]["virtual_address"]
```

`_name_order = [EXPORT_TABLE, IMPORT_TABLE, RESOURCE_TABLE, EXCEPTION_TABLE, CERTIFICATE_TABLE, BASE_RELOCATION_TABLE, DEBUG, ARCHITECTURE, GLOBAL_PTR, TLS_TABLE, LOAD_CONFIG_TABLE, BOUND_IMPORT, IAT, DELAY_IMPORT_DESCRIPTOR, CLR_RUNTIME_HEADER]`. Important: indexing is **positional by `raw_obj[i]`**, not matched by name — the `name` field is ignored in processing. It relies on LIEF returning the 16 PE data directories in standard order; only the first 15 are used (the 16th/reserved is dropped). Layout: `[size0, rva0, size1, rva1, ...]`.

---

## raw JSON vs. process(), and top-level flow

`PEFeatureExtractor.raw_features(bytez)`:
- `lief_binary = lief.PE.parse(list(bytez))`; on `lief.bad_format/bad_file/pe_error/parser_error/read_out_of_bound/RuntimeError` → `lief_binary = None` (all the None-branches above then apply). Other exceptions re-raise.
- Returns `{"sha256": sha256(bytez).hexdigest(), "histogram": [...], "byteentropy":[...], "strings":{...}, "general":{...}, "header":{...}, "section":{...}, "imports":{...}, "exports":[...], "datadirectories":[...]}` — this is the JSONL `raw_features` the dataset ships.

`process_raw_features(raw_obj)`: `np.hstack([fe.process_raw_features(raw_obj[fe.name]) for fe in self.features]).astype(np.float32)` — order = the table above.

`feature_vector(bytez) = process_raw_features(raw_features(bytez))`.

---

## C# parity checklist (where byte-for-byte breaks)

1. **MurmurHash3_x86_32, seed 0, signed** + `abs(h)%N` (with the `INT_MIN` special case) + `sign=(h>=0)?+1:-1` + UTF-8 token bytes + **summed** collisions. Accumulate in `double`, cast to `float32` per group. This governs header (5×10), section (5×50), imports (256+1024), exports (128).
2. **Exact LIEF enum spellings** (`str(x).split('.')[-1]`) for machine, header characteristics, subsystem, dll_characteristics, magic, section characteristics/props. Any spelling drift changes the hash.
3. **LIEF section entropy** double value reproduced exactly (feeds a signed float into the pair-hash sum).
4. **Section entry-name hashed per-character** (the `transform([entry_string])` string-iteration quirk).
5. **Import token casing**: `lib.lower() + ':' + name`, function name preserves original case; exports/entry-name not lowercased.
6. **ByteEntropy**: window 2048 / step 1024, `p=c/2048` constant, high-nibble `>>4`, `H*2`, `int()` truncation, `Hbin==16→15`, trailing partial window dropped.
7. **Strings**: `[\x20-\x7f]{5,}` on raw bytes; `printables` used both as raw feature and as the 96-bin divisor; `avlength` mean; `paths/urls` case-insensitive, `registry/HKEY_`/`MZ` case-sensitive.
8. **float32 everywhere** with float64 intermediates matching numpy (`bincount`, `sum`, `log2`, division order). `astype(np.float32)` at each group and once more at the top-level hstack.
9. **None/parse-failure branches** must zero-fill identically (LIEF parse failure yields a well-defined all-defaults vector).

**Sources:** [ember/features.py (elastic/ember, master)](https://raw.githubusercontent.com/elastic/ember/master/ember/features.py) · [sklearn `_hashing_fast.pyx`](https://raw.githubusercontent.com/scikit-learn/scikit-learn/main/sklearn/feature_extraction/_hashing_fast.pyx)