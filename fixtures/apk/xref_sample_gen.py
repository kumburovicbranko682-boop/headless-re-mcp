"""Rebuild ``xref_sample.apk`` for the apk.xrefs method-resolution live gate.

The gate needs a real ``classes.dex`` with a known call graph so androguard's
cross-reference analysis has something concrete to resolve:

  * ``Lcom/example/re/Sample;->callee()V`` is invoked by ``caller()`` and
    ``alsoCallsCallee()`` -- two real callers.
  * ``lonely()`` and ``caller()`` exist but are never called -- zero callers.
  * any other name (e.g. ``doesNotExist``) matches no method at all.

That mix is exactly what separates the three cases apk.xrefs must not conflate:
a called method, a method that exists but is uncalled, and a name that resolves
to nothing.

The DEX is a checked-in binary fixture; CI only needs androguard (pip) to *read*
it, never a DEX toolchain to *build* it. Rebuild is a one-time developer step
that needs the smali assembler (https://github.com/google/smali):

    # 1. assemble the hand-written smali into a classes.dex
    java -cp 'smali-2.5.2.jar:dexlib2-2.5.2.jar:util-2.5.2.jar:\
antlr-runtime-3.5.2.jar:jcommander-1.64.jar:stringtemplate-3.2.1.jar:\
guava-27.1-android.jar' org.jf.smali.Main assemble \
        fixtures/apk/xref_sample.smali -o classes.dex
    # 2. wrap it in a minimal APK (AndroidManifest is a placeholder: the DEX
    #    analysis the gate exercises does not depend on a valid binary manifest)
    python fixtures/apk/xref_sample_gen.py classes.dex fixtures/apk/xref_sample.apk
"""

from __future__ import annotations

import sys
import zipfile
from pathlib import Path


def build(dex_path: Path, out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(out_path, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00manifest")
        archive.write(dex_path, "classes.dex")


if __name__ == "__main__":
    dex = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("classes.dex")
    target = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("xref_sample.apk")
    build(dex, target)
    print(f"wrote {target} from {dex}")
