# Presidio Image Redactor + Structured Data

Capability catalog of Microsoft Presidio's non-text PII facilities — used to
size the gap against octarine (currently text-only).

## Source files reviewed

Image redactor (`presidio-image-redactor`):

- <https://github.com/microsoft/presidio/blob/main/presidio-image-redactor/presidio_image_redactor/image_redactor_engine.py>
- <https://github.com/microsoft/presidio/blob/main/presidio-image-redactor/presidio_image_redactor/image_analyzer_engine.py>
- <https://github.com/microsoft/presidio/blob/main/presidio-image-redactor/presidio_image_redactor/image_processing_engine.py>
- <https://github.com/microsoft/presidio/blob/main/presidio-image-redactor/presidio_image_redactor/ocr.py>
- <https://github.com/microsoft/presidio/blob/main/presidio-image-redactor/presidio_image_redactor/tesseract_ocr.py>
- <https://github.com/microsoft/presidio/blob/main/presidio-image-redactor/presidio_image_redactor/document_intelligence_ocr.py>
- <https://github.com/microsoft/presidio/blob/main/presidio-image-redactor/presidio_image_redactor/bbox.py>
- <https://github.com/microsoft/presidio/blob/main/presidio-image-redactor/presidio_image_redactor/dicom_image_redactor_engine.py>
- <https://github.com/microsoft/presidio/blob/main/presidio-image-redactor/presidio_image_redactor/entities/image_recognizer_result.py>
- <https://github.com/microsoft/presidio/blob/main/presidio-image-redactor/pyproject.toml>
- <https://github.com/microsoft/presidio/blob/main/presidio-image-redactor/README.md>
- <https://microsoft.github.io/presidio/image-redactor/>

Structured (`presidio-structured`):

- <https://github.com/microsoft/presidio/blob/main/presidio-structured/presidio_structured/structured_engine.py>
- <https://github.com/microsoft/presidio/blob/main/presidio-structured/presidio_structured/analysis_builder.py>
- <https://github.com/microsoft/presidio/blob/main/presidio-structured/presidio_structured/config/structured_analysis.py>
- <https://github.com/microsoft/presidio/blob/main/presidio-structured/presidio_structured/data/data_processors.py>
- <https://github.com/microsoft/presidio/blob/main/presidio-structured/presidio_structured/data/data_reader.py>
- <https://github.com/microsoft/presidio/blob/main/presidio-structured/README.md>
- <https://microsoft.github.io/presidio/structured/>

---

## Image redaction

### Supported input formats

Input is a **PIL (Pillow) `Image.Image`** object — there's no format
enumeration at the engine; whatever PIL opens can be redacted. Practical
implications:

- PNG, JPEG, BMP, GIF, TIFF, WebP (via Pillow's built-in codecs).
- The Tesseract OCR backend accepts `PIL Image | numpy.ndarray | file path str`.
- The Azure Document Intelligence backend additionally accepts raw `bytes`.
- **DICOM** (`*.dcm` / `*.dicom`) handled by a separate
  `DicomImageRedactorEngine` that takes a `pydicom.dataset.FileDataset`.
- **No PDF support.** PDFs would have to be rasterized externally first.
- **No video / multi-frame support** for non-DICOM images. DICOM multi-frame
  is not specifically documented and the directory walker only globs `.dcm` /
  `.dicom` extensions.

### OCR engines used

The OCR backend is **pluggable** behind an abstract base class
(`presidio_image_redactor.ocr.OCR`) with a single `perform_ocr(image,
**kwargs) -> dict` method. The dict shape is Tesseract-style:
`{left, top, width, height, conf, text}` as parallel lists.

Two concrete backends ship in the package:

| Backend | Class | Notes |
|---------|-------|-------|
| **Tesseract** (default) | `TesseractOCR` | Wraps `pytesseract.image_to_data(...)`. Requires native Tesseract install. Tested against v5.2.0. |
| **Azure AI Document Intelligence** (cloud) | `DocumentIntelligenceOCR` | Requires Azure endpoint + API key (or env vars `DOCUMENT_INTELLIGENCE_ENDPOINT` / `DOCUMENT_INTELLIGENCE_KEY`). Single-page only — raises if a result returns >1 page. |

`DocumentIntelligenceOCR` exposes a fixed list of model IDs (passed
unmodified to Azure):

- `prebuilt-document` (default)
- `prebuilt-read`
- `prebuilt-layout`
- `prebuilt-contract`
- `prebuilt-healthInsuranceCard.us`
- `prebuilt-invoice`
- `prebuilt-receipt`
- `prebuilt-idDocument`
- `prebuilt-businessCard`

Only **word-level** OCR output is consumed for PII matching — layout, lines,
paragraphs, and tables from Document Intelligence are discarded.

A custom backend can be plugged in by subclassing `OCR` and passing the
instance to `ImageAnalyzerEngine(ocr=...)`.

### Redaction methods

Only one redaction method is implemented: **solid fill rectangle** drawn via
`PIL.ImageDraw.Draw.rectangle(..., fill=fill)` over each detected bounding box.

- `fill` parameter: `int` (0-255 grayscale) or `(R, G, B)` tuple.
- Default fill is black `(0, 0, 0)`.
- **No blur, no pixelation, no mosaic, no inpainting.** If users want
  alternatives they must process bboxes themselves.
- For DICOM, `fill` is a string `"contrast"` (default) or `"background"` —
  the engine derives the actual pixel value from a crop of the image corners
  (most-common pixel → background; least-common → contrast).

Preprocessing (improves OCR, does not redact) is also pluggable via
`ImagePreprocessor` and includes:

- `BilateralFilter` (cv2 bilateral filter, grayscale)
- `SegmentedAdaptiveThreshold` (cv2 adaptive thresholding driven by image
  contrast)
- `ImageRescaling` (cv2 resize for very small / very large images)
- `ContrastSegmentedImageEnhancer` (full pipeline: bilateral + contrast
  improvement + adaptive threshold + Otsu + rescale)

`ImageAnalyzerEngine` records `scale_factor` from preprocessing and
back-scales the OCR bboxes before they are returned, so callers always see
coordinates in the original image's pixel space.

### DICOM-specific support

`DicomImageRedactorEngine` (subclass of `ImageRedactorEngine`) adds
medical-imaging-specific behavior.

**Tags scrubbed (pixel data only — see caveat).** The engine does NOT
hardcode a tag list like `(0x0010, 0x0010) PatientName`. Instead it
introspects metadata by **substring match on `element.name`**:

```python
# _get_text_metadata in dicom_image_redactor_engine.py
if "name" in element.name.lower():     -> treated as is_name=True
if "patient" in element.name.lower():  -> treated as is_patient=True
```

This matches (case-insensitive substring on the human-readable element
name) tags such as:

- `PatientName` (0010,0010)
- `PatientID` (0010,0020)
- `PatientBirthDate` (0010,0030)
- `PatientSex` (0010,0040)
- `PatientAddress` (0010,1040)
- `ReferringPhysicianName` (0008,0090)
- `PerformingPhysicianName` (0008,1050)
- `OperatorsName` (0008,1070)
- `OtherPatientNames`, `OtherPatientIDs`, etc.
- Anything with "Name" or "Patient" in the official DICOM keyword.

All values from `is_name`-tagged and `is_patient`-tagged elements are then
used to build an **ad-hoc Presidio `PatternRecognizer`** whose patterns
are applied to the OCR'd text in the pixel data. The intent is "burn out
on the rendered image any words that also appear in the patient
metadata."

**Augmentation.** Each name token is exploded into multiple casings before
being added to the recognizer: `original`, `UPPER`, `lower`, `Title`, plus
each variant split on whitespace, with `^` and `-` collapsed to spaces
(DICOM PN VR uses `^` to separate components). A small generic PHI list is
also appended: `["[M]", "[F]", "[X]", "[U]", "M", "F", "X", "U"]`.

**CRITICAL CAVEAT — metadata is NOT scrubbed.** The Presidio docs say
explicitly:

> Presidio only redacts pixel data and does not scrub text PII which may
> exist in the DICOM metadata.

DICOM metadata de-identification (e.g., DICOM PS3.15 Annex E Basic
Confidentiality Profile, the dozens of tags like StudyDescription,
InstitutionName, AccessionNumber, etc.) is **out of scope** of this engine.
The docs recommend running Presidio for pixel redaction and then a separate
metadata scrubber (e.g., `pydicom`'s anonymization or `dicom-deid`).

**Pixel data redaction details:**

- Grayscale detection via `PhotometricInterpretation in {"MONOCHROME1",
  "MONOCHROME2"}`.
- VOI LUT applied via `pydicom.pixel_data_handlers.util.apply_voi_lut` when
  `WindowWidth` is present, then rescaled to uint8.
- Pixel array padded before OCR (`padding_width=25` default) to help
  Tesseract on text near edges; padding is removed from final bboxes.
- Fill color computed from corners of the original pixel array
  (`crop_ratio=0.75` default) — either most-common pixel ("background") or
  least-common ("contrast").
- After redaction the engine writes back via
  `instance.pixel_array[top:top+h, left:left+w] = box_color`, repacks via
  `tobytes()` into `PixelData`.
- If the original pixel data was compressed, the engine attempts to
  recompress (forces `YBR_FULL` photometric interp when the source was
  YBR-family). `python-gdcm` is a hard dependency for decompression.
- ImageIconSequence tag is checked but only as a heuristic.

**Bulk APIs (DICOM only):**

- `redact_from_file(input_dicom_path, output_dir, ...)` — single file,
  copies the file first.
- `redact_from_directory(input_dicom_path, output_dir, ...)` — recursive
  glob for `*.dcm` and `*.dicom` (case-insensitive). No parallelism — it's
  a for-loop over files.
- Both can `save_bboxes=True` to dump per-file JSON sidecars next to the
  redacted DCM.

### Bounding box API

The primary `ImageRedactorEngine` exposes two surface APIs:

```python
redact(image, fill=(0,0,0), ocr_kwargs=None, ad_hoc_recognizers=None,
       **text_analyzer_kwargs) -> PIL.Image.Image
redact_and_return_bbox(image, ...) -> tuple[PIL.Image.Image, list[ImageRecognizerResult]]
```

`ImageRecognizerResult` is a small dataclass (subclass of
`presidio_analyzer.RecognizerResult`) carrying:

- `entity_type`, `start`, `end`, `score` (from the analyzer)
- `left`, `top`, `width`, `height` (pixel coordinates in the original image)

There is also an **OCR confidence threshold** knob:
`ocr_kwargs={"ocr_threshold": 60.0}` filters word boxes with confidence
below the threshold before PII analysis.

An `allow_list` (passed through `text_analyzer_kwargs`) can exempt specific
strings from being redacted.

An `ad_hoc_recognizers` parameter accepts a list of
`presidio_analyzer.PatternRecognizer` instances to layer on top of the
default analyzer recognizers — the same mechanism the DICOM engine uses
internally to inject metadata-derived patterns.

### Bbox processor / merge logic

`BboxProcessor` (in `bbox.py`) is a static-method utility class:

- `get_bboxes_from_ocr_results(ocr_dict) -> list[dict]` — flattens the
  Tesseract-style parallel-list dict into per-word dicts; drops boxes whose
  text is empty.
- `get_bboxes_from_analyzer_results(analyzer_results)` — converts
  `ImageRecognizerResult` objects to plain dicts.
- `remove_bbox_padding(bboxes, padding_width)` — subtracts padding pixels
  added during OCR preprocessing (clamps to 0). Preserves `label` and/or
  `entity_type` keys if present.
- `match_with_source(all_pos, pii_source_dict, detected_pii, tolerance=50)`
  — matches an analyzer-produced bbox against a ground-truth list with a
  tolerance on each of left/top/width/height. Used by the eval tooling, not
  in the runtime redaction path.

**Notably absent:** there is **no bbox merging / NMS / overlap suppression**.
If the analyzer detects the same entity twice or two entities cover
overlapping OCR words, multiple rectangles get drawn (which is fine for
opaque fills but produces duplicate boxes if you consume them downstream).

Inside `ImageAnalyzerEngine.map_analyzer_results_to_bounding_boxes`, each
analyzer hit is mapped to the OCR word(s) at the same character offsets in
the joined OCR text. When an entity span covers multiple OCR words, the
iterator walks forward and produces one bbox per OCR word inside the span —
no attempt is made to fuse them into a single tight rectangle.

There's also `get_pii_bboxes(ocr_bboxes, analyzer_bboxes)` and
`add_custom_bboxes(image, bboxes, ...)` on `ImageAnalyzerEngine` for the
**PII Verify** workflow (Matplotlib overlay rendering of red boxes for PII
and blue boxes for non-PII words — a debugging / labeling visualization).

---

## Structured data redaction

### Supported input types

| Input | Builder | Processor | Notes |
|-------|---------|-----------|-------|
| `pandas.DataFrame` | `PandasAnalysisBuilder` | `PandasDataProcessor` (default) | Native tabular path. |
| `dict` (JSON-shaped, arbitrary nesting) | `JsonAnalysisBuilder` | `JsonDataProcessor` | Dotted-path keys like `"user.email"`. |
| CSV file | (read via `CsvReader.read(path) -> DataFrame`) | Pandas path | Just a thin `pd.read_csv` wrapper. |
| JSON file | (read via `JsonReader.read(path) -> dict`) | JSON path | `json.load` wrapper. |

**Explicitly NOT supported** (per the upstream docs' "future work" list):

- PySpark / Spark DataFrames
- Parquet, Arrow, Avro, ORC
- Polars
- SQL / database row iterators
- Streaming readers

Lists of JSON dicts are partially supported — `JsonDataProcessor` recurses
into top-level lists and applies the analysis per item — but the docs
caution "Nesting objects in lists is not supported in `JsonAnalysisBuilder`
for now"; the workaround is to manually build a `StructuredAnalysis` with
dotted paths.

### Schema analysis

There is **no dtype / column-type inference** — schema analysis is
entity-based, not type-based. The builder samples cell values, runs them
through `BatchAnalyzerEngine`, and produces a `dict[str, str]` mapping
each column / key to a single PII entity type (the chosen one per the
strategy below).

For DataFrames:

- `PandasAnalysisBuilder.generate_analysis(df, n=None, language="en",
  selection_strategy="most_common", mixed_strategy_threshold=0.5)`.
- Samples `n` rows (default = all rows) with a fixed `random_state=123`.
- Analyzes **each column independently** by passing
  `[val for val in df[column]]` to `batch_analyzer.analyze_iterator(...)`.
- Three column-level selection strategies (the per-column "what is this
  column's entity type?" decision):
  - `"most_common"` (default) — picks the most frequent entity type; score
    is the proportion of cells where that type appeared.
  - `"highest_confidence"` — picks the entity type with the single highest
    confidence score across all cells.
  - `"mixed"` — uses highest-confidence if its score exceeds
    `mixed_strategy_threshold`, else falls back to most-common.
- Columns where no entity is detected are tagged `NON_PII` and excluded
  from the final mapping.

For JSON:

- `JsonAnalysisBuilder.generate_analysis(data, language="en")`.
- Calls `batch_analyzer.analyze_dict(...)` once on the whole dict.
- Recurses nested dicts via dotted keys (`"user.name"`, `"user.address.city"`).
- Always uses the **first** `RecognizerResult` returned for each key
  (`next(iter(result.recognizer_results), None)`) — no strategy selection.

Both builders accept `n_process` and `batch_size` knobs that are forwarded
to the underlying `BatchAnalyzerEngine` (which uses spaCy's `pipe()` for
multiprocessing of the text analysis stage).

The result is a `StructuredAnalysis(entity_mapping: dict[str, str])` — a
simple Pydantic-style dataclass. Users can also construct one manually to
bypass automatic detection entirely.

### Tabular vs nested handling

- **Tabular path (`PandasDataProcessor._process`)** operates
  **column-by-column**: for each PII column, it iterates rows via
  `df.itertuples(index=True)` and calls `data.at[row.Index, key] =
  operated_text`. The operator is applied **per cell**, not per column en
  masse — there is no column-wise vectorization. (This means very large
  DataFrames will be slow; the work is row-major Python.)
- **Nested path (`JsonDataProcessor._process`)** splits each key on `.`,
  walks `_get_nested_value` recursively, applies the operator, and walks
  back via `_set_nested_value`. Lists are traversed; numeric indices in the
  path navigate list positions, string segments select dict keys. The
  recursion will set the operated value back at the same path.

### Operators supported on structured data

Operators are **not implemented in `presidio-structured`** — it delegates
to `presidio_anonymizer.operators.OperatorsFactory`. The structured engine
hardcodes `OperatorType.Anonymize` (so de-anonymization operators are
**not** wired through), and supports any anonymize operator the anonymizer
package ships:

- `replace` (the default — replaces matched text with a configurable string,
  by default `<ENTITY_TYPE>`)
- `redact` (remove the text entirely)
- `hash` (SHA-256/512/MD5)
- `mask` (character masking with `masking_char`, `chars_to_mask`, `from_end`)
- `encrypt` (AES with caller-supplied key)
- `keep` (no-op pass-through)
- `custom` (caller-supplied `lambda x: ...`)

Operators are configured per entity type via
`Dict[str, OperatorConfig]`, e.g.:

```python
operators = {
    "PERSON":        OperatorConfig("replace", {"new_value": "REDACTED"}),
    "EMAIL_ADDRESS": OperatorConfig("custom",  {"lambda": fake.safe_email}),
    "DEFAULT":       OperatorConfig("replace"),  # fallback
}
```

A `"DEFAULT"` operator is auto-inserted (set to `replace`) if the caller
doesn't supply one.

---

## Cross-cutting features

### Batch processing

- **Image (standard):** No native batch API. Process one PIL `Image` at a
  time. The HTTP service (`POST /redact`) takes a single multipart upload.
- **Image (DICOM):** `redact_from_directory(input_dir, output_dir, ...)`
  recursively processes all `.dcm` / `.dicom` files sequentially. Single-
  threaded — no `multiprocessing` / `concurrent.futures` involved.
- **Structured:** Implicit batch — `anonymize(df, analysis, ...)` processes
  the whole DataFrame/dict in one call. `PandasAnalysisBuilder` exposes
  `n_process` and `batch_size` for the analysis stage (forwarded to
  spaCy's pipeline) but the anonymization stage is single-threaded
  per-cell.

### Async support

**None.** All public APIs are synchronous. There are no `async def`
entry points anywhere in either package. The Azure Document Intelligence
client is used via its synchronous `poller.result()` path even though the
underlying SDK has async variants.

### Streaming

**None.** Both packages assume the entire input fits in memory:

- Images are PIL objects already decoded into pixel arrays.
- Structured input is a fully-materialized DataFrame or dict.
- No row-iterator / chunked-CSV / streaming-JSON consumer.
- DICOM bulk processing reads each file fully via `pydicom.dcmread`.

---

## Anything notable / unusual

1. **The OCR contract leaks Tesseract's shape.** Every backend (Document
   Intelligence included) must reshape its output into Tesseract's
   parallel-list dict (`{left, top, width, height, conf, text}`).
   `DocumentIntelligenceOCR._page_to_bboxes` explicitly does this with the
   comment "Presidio supports tesseract format of output only, so we
   format in the same way." Polygons are flattened to axis-aligned bboxes,
   throwing away skew/rotation info.

2. **DICOM redaction is half a story.** The package name suggests DICOM
   de-identification but the engine ONLY touches pixel data — DICOM
   metadata tags (where most PHI lives) are explicitly out of scope. This
   is a gap callers must fill themselves and the docs say so. For a true
   PS3.15-conformant de-id pipeline you need a separate tool.

3. **No bbox merging.** Multiple word-level rectangles for the same entity
   are drawn as separate fills. Fine visually, awkward if you're consuming
   the bbox list as an annotation feed.

4. **DICOM tag detection is by substring on the human-readable name**,
   not by tag number or VR. This is fragile (works on `PatientName` /
   `OtherPatientNames` / `ReferringPhysicianName`, but misses
   `InstitutionName`, `AccessionNumber`, `StudyID`, etc., and would
   silently break on any pydicom version that renames an element).

5. **DICOM name augmentation is unusually thorough** — every detected name
   token is expanded to four casings (original / UPPER / lower / Title)
   AND each casing is split on whitespace into individual word recognizers,
   so OCR'd surnames are found even if only part of the name lands in the
   pixel data. The DICOM VR-specific `^` (component separator) is
   collapsed to space first.

6. **Structured anonymization is row-major Python.** `PandasDataProcessor`
   uses `itertuples + df.at[...]` — there's no Series-level vectorized
   apply, no `df.apply(axis=0)`. This will be slow on large frames and
   doesn't take advantage of pandas' columnar storage.

7. **`JsonAnalysisBuilder` only keeps the first recognizer result per
   key**, silently. If a JSON field's value triggers both PERSON and
   LOCATION, whichever came first in the iterator wins. The Pandas
   builder has three selection strategies; the JSON builder has none.

8. **Hardcoded `OperatorType.Anonymize`** in structured —
   `OperatorsFactory.create_operator_class(name, OperatorType.Anonymize)`
   is literally pinned, so de-anonymization (encrypt/decrypt round-trip) is
   not exposed through the structured engine even though
   `presidio-anonymizer` supports it.

9. **Heavy native deps for "just redaction":** `presidio-image-redactor`
   pulls in OpenCV (`opencv-python`), pydicom, GDCM (`python-gdcm`),
   matplotlib, Azure Form Recognizer client, pytesseract, and pypng even
   if you only want to redact a PNG with the default Tesseract path. The
   package is marked **beta / not production ready** in the docs.

10. **Image redactor is a beta on a 0.0.x line** (`version = "0.0.58"`) —
    structured uses the same `presidio-analyzer ^2.2` machinery, so
    accuracy of detection is identical to text-Presidio; these packages
    are pure delivery wrappers, not new detection logic.
