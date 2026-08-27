"""Live apktool resource-decode gate: binary AXML/ARSC back to readable XML.

The android tools gate round-trips only a bare manifest, so apktool's resource
pipeline -- compiling res/values into resources.arsc plus a binary
AndroidManifest.xml on build, and decoding both back into readable XML on
decode -- is never proven anywhere. This gate builds an APK whose skeleton
carries real value resources, then asserts with independent evidence:

- the built APK really contains *binary* artifacts: the manifest starts with
  the AXML chunk magic (not text) and resources.arsc with the ARSC table magic,
  with the marker string compiled into the table (read straight from the zip,
  not through apktool);
- a full decode recovers a parseable text manifest with the right package and
  res/values/strings.xml with the exact marker entries, plus the smali class;
- decode with no_resources=True actually changes behavior: resources.arsc is
  kept raw, no res/ tree appears, the manifest stays binary and the report
  says has_resources=False.

The apktool.yml requests framework id 1 so apktool uses its bundled framework
table; no Android SDK is needed. Skips honestly when apktool (needs a JRE) is
not configured. skip != pass.
"""

from __future__ import annotations

import struct
import zipfile
from pathlib import Path
from xml.etree import ElementTree

import pytest

from headless_re_mcp.backends.apktool.client import ApktoolClient
from headless_re_mcp.config import Settings

_PACKAGE = "com.headlessre.resgate"
_MARKER = "H3adl3ss-RE-resdecode-9f2"

_MANIFEST = (
    '<?xml version="1.0" encoding="utf-8"?>\n'
    '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
    f'package="{_PACKAGE}">\n</manifest>\n'
)
# usesFramework id 1 makes apktool link against its bundled framework resource
# table, which is what lets aapt2 compile res/values without an Android SDK.
_APKTOOL_YML = (
    "!!brut.androlib.meta.MetaInfo\n"
    "apkFileName: out.apk\n"
    "usesFramework:\n"
    "  ids:\n"
    "  - 1\n"
)

_STRINGS_XML = (
    '<?xml version="1.0" encoding="utf-8"?>\n'
    "<resources>\n"
    f'    <string name="gate_marker">{_MARKER}</string>\n'
    '    <string name="gate_title">Resource Gate</string>\n'
    "</resources>\n"
)

_SMALI = """.class public Lcom/headlessre/resgate/Res;
.super Ljava/lang/Object;

.method public constructor <init>()V
    .registers 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    return-void
.end method
"""

# Chunk magics from the Android binary formats: an AXML document starts with
# chunk type 0x0003 / header size 0x0008, an ARSC table with 0x0002 / 0x000c.
_AXML_MAGIC = (0x0003, 0x0008)
_ARSC_MAGIC = (0x0002, 0x000C)


def _chunk_magic(blob: bytes) -> tuple[int, int]:
    kind, header_size = struct.unpack_from("<HH", blob, 0)
    return (int(kind), int(header_size))


def _build_resource_apk(client: ApktoolClient, tmp_path: Path) -> Path:
    skeleton = tmp_path / "skeleton"
    smali_dir = skeleton / "smali" / "com" / "headlessre" / "resgate"
    smali_dir.mkdir(parents=True)
    values = skeleton / "res" / "values"
    values.mkdir(parents=True)
    (skeleton / "AndroidManifest.xml").write_text(_MANIFEST, encoding="utf-8")
    (skeleton / "apktool.yml").write_text(_APKTOOL_YML, encoding="utf-8")
    (smali_dir / "Res.smali").write_text(_SMALI, encoding="utf-8")
    (values / "strings.xml").write_text(_STRINGS_XML, encoding="utf-8")
    out = tmp_path / "out.apk"
    built = client.build(skeleton, out)
    assert Path(built["apk"]).is_file()
    return out


@pytest.mark.integration
def test_apktool_decodes_compiled_resources_back_to_readable_xml(tmp_path: Path) -> None:
    settings = Settings.load()
    client = ApktoolClient(apktool=settings.apktool, apksigner=settings.apksigner)
    if not client.available:
        pytest.skip("apktool not configured (HEADLESS_RE_APKTOOL / PATH) — skip != pass")

    apk = _build_resource_apk(client, tmp_path)

    # Independent evidence the build produced *binary* Android artifacts: read
    # the zip directly instead of trusting apktool's own report.
    with zipfile.ZipFile(apk) as zf:
        names = set(zf.namelist())
        assert {"AndroidManifest.xml", "resources.arsc", "classes.dex"} <= names, names
        raw_manifest = zf.read("AndroidManifest.xml")
        assert not raw_manifest.startswith(b"<?xml"), "manifest was not compiled to AXML"
        assert _chunk_magic(raw_manifest) == _AXML_MAGIC, raw_manifest[:8].hex()
        raw_arsc = zf.read("resources.arsc")
        assert _chunk_magic(raw_arsc) == _ARSC_MAGIC, raw_arsc[:8].hex()
        # The marker really was compiled into the resource table's string pool.
        assert (
            _MARKER.encode("utf-8") in raw_arsc or _MARKER.encode("utf-16-le") in raw_arsc
        ), "marker missing from resources.arsc"

    # Full decode: binary AXML and the resource table come back as readable XML.
    decoded = client.decode(apk, tmp_path / "decoded")
    assert decoded["has_resources"] is True
    assert decoded["smali_dirs"] == ["smali"]

    manifest_path = decoded["manifest"]
    assert manifest_path is not None
    manifest_text = Path(manifest_path).read_text(encoding="utf-8")
    assert manifest_text.startswith("<?xml"), manifest_text[:80]
    root = ElementTree.fromstring(manifest_text)
    assert root.tag == "manifest"
    assert root.get("package") == _PACKAGE, manifest_text

    strings_path = Path(decoded["decoded_dir"]) / "res" / "values" / "strings.xml"
    assert strings_path.is_file(), sorted(
        str(p) for p in Path(decoded["decoded_dir"]).rglob("*.xml")
    )
    entries = {
        node.get("name"): node.text
        for node in ElementTree.parse(strings_path).getroot().iter("string")
    }
    assert entries.get("gate_marker") == _MARKER, entries
    assert entries.get("gate_title") == "Resource Gate", entries

    smali_out = Path(decoded["decoded_dir"]) / "smali" / "com" / "headlessre" / "resgate"
    assert (smali_out / "Res.smali").is_file()
    assert ".class public Lcom/headlessre/resgate/Res;" in (smali_out / "Res.smali").read_text(
        encoding="utf-8"
    )


@pytest.mark.integration
def test_apktool_no_resources_flag_keeps_the_resource_table_raw(tmp_path: Path) -> None:
    settings = Settings.load()
    client = ApktoolClient(apktool=settings.apktool, apksigner=settings.apksigner)
    if not client.available:
        pytest.skip("apktool not configured (HEADLESS_RE_APKTOOL / PATH) — skip != pass")

    apk = _build_resource_apk(client, tmp_path)
    decoded = client.decode(apk, tmp_path / "decoded_raw", no_resources=True)
    assert decoded["has_resources"] is False

    out_dir = Path(decoded["decoded_dir"])
    assert not (out_dir / "res").is_dir()
    # The table is carried through untouched and the manifest stays binary:
    # -r means "do not decode resources", not "drop them".
    raw_arsc = (out_dir / "resources.arsc").read_bytes()
    assert _chunk_magic(raw_arsc) == _ARSC_MAGIC, raw_arsc[:8].hex()
    raw_manifest = (out_dir / "AndroidManifest.xml").read_bytes()
    assert _chunk_magic(raw_manifest) == _AXML_MAGIC, raw_manifest[:8].hex()
    # smali is still produced: the flag scopes resource decoding only.
    assert (out_dir / "smali" / "com" / "headlessre" / "resgate" / "Res.smali").is_file()
