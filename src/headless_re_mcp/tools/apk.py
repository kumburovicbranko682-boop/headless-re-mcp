"""Protocol-independent apk.* tool definitions (Android static analysis)."""

from __future__ import annotations

from typing import Annotated, Any

from pydantic import Field

from headless_re_mcp.core.models import Result
from headless_re_mcp.core.service import AnalysisService, JsonObject
from headless_re_mcp.tools.binding import BoundTool, ToolSetBuilder


def _dump(result: Result[JsonObject]) -> dict[str, Any]:
    value = result.model_dump(mode="json")
    if not isinstance(value, dict):
        raise TypeError("result envelope did not serialize to an object")
    return value


def build_apk_tools(analysis: AnalysisService) -> tuple[BoundTool, ...]:
    tools = ToolSetBuilder()

    @tools.tool(name="apk.open")
    def apk_open(session_id: str) -> dict[str, Any]:
        """Parse an APK session's identity.

        Answers with package, version_name, version_code, min_sdk, target_sdk,
        native_abis, main_activity, permission_count and opened. There is no
        version, sdk or abis field.
        """
        return _dump(analysis.apk_open(session_id))

    @tools.tool(name="apk.manifest")
    def apk_manifest(session_id: str) -> dict[str, Any]:
        """Return the decoded AndroidManifest.xml for the APK session.

        Answers with package and manifest_xml, plus truncated when the XML
        was cut at the buffer.
        """
        return _dump(analysis.apk_manifest(session_id))

    @tools.tool(name="apk.permissions")
    def apk_permissions(session_id: str) -> dict[str, Any]:
        """List declared and requested permissions.

        Answers with permissions, requested_permissions, count, and has_more
        so a list that filled the cap is not read as every permission. There
        is no declared or requested field.
        """
        return _dump(analysis.apk_permissions(session_id))

    @tools.tool(name="apk.certificates")
    def apk_certificates(session_id: str) -> dict[str, Any]:
        """List signing certificates and which signature schemes signed the APK.

        Answers with certificates (subject, issuer, serial, sha256),
        signature_files, and has_more so a list that filled the cap is not
        read as every signer. The signing state is reported per scheme:
        v1_signed (JAR/META-INF), v2_signed and v3_signed (APK Signing
        Block), plus signed for "any scheme" -- a modern app is often v2/v3
        with no v1 at all, so v1_signed alone would read as unsigned. There
        is no certs or signatures field.
        """
        return _dump(analysis.apk_certificates(session_id))

    @tools.tool(name="apk.components")
    def apk_components(session_id: str) -> dict[str, Any]:
        """List activities, services, receivers, and providers.

        Answers with activities, services, receivers, providers,
        main_activity, and has_more so a list that filled the cap is not
        read as every component. There is no components field.

        For attack-surface triage, details maps each of those four kinds to
        per-component records: name, exported (Android's effective value --
        the explicit android:exported when set, otherwise inferred: an
        intent-filter for activities/services/receivers, and the API-17 default
        flip for providers -- exported below targetSdk 17, private at/above),
        exported_explicit (the raw attribute,
        or null when unset so an inferred value is distinguishable from a
        declared one), has_intent_filter, and permission when the component
        is guarded by one. When a component declares intent-filters, the
        record also carries intent_filters: a list of {actions, categories,
        data} where data holds the deep-link specs (scheme, host, port, path*,
        mimeType) -- the implicit-intent entry points reachable from other
        apps. exported is a convenience map of each kind to just the names
        that are reachable from other apps.
        """
        return _dump(analysis.apk_components(session_id))

    @tools.tool(name="apk.native_libs")
    def apk_native_libs(session_id: str) -> dict[str, Any]:
        """List bundled native libraries and their ABIs.

        Answers with native_libs, abis, count, and has_more so a list that
        filled the cap is not read as every .so. There is no libs or
        libraries field.
        """
        return _dump(analysis.apk_native_libs(session_id))

    @tools.tool(name="apk.files")
    def apk_files(
        session_id: str,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=5000)] = 1000,
    ) -> dict[str, Any]:
        """List the APK archive's entries with size and a triage category.

        native_libs only sees lib/*.so; this shows the rest of the archive --
        how many dex, whether there is an assets/ tree (a common hiding place
        for a bundled dex/JS payload or config), the resource table, the signer
        files -- which otherwise needed a full apktool decode. Sizes come from
        the zip directory (no decompression), so it is cheap on a large app.

        Answers with files, each carrying name, size (uncompressed bytes),
        compressed (on-disk bytes) and category (one of manifest, dex,
        native_lib, resource, asset, signature, other), plus count, total,
        offset and has_more so a page that filled the limit is not read as the
        whole archive. categories maps each category to its count across the
        whole archive (not just the page), and total_bytes is the summed
        uncompressed size. A pathologically long entry name is cut and flagged
        name_truncated. There is no entries or names field.
        """
        return _dump(analysis.apk_files(session_id, offset=offset, limit=limit))

    @tools.tool(name="apk.extract_native_lib")
    def apk_extract_native_lib(session_id: str, entry: str) -> dict[str, Any]:
        """Extract one bundled native library (.so) for r2/Ghidra analysis.

        entry is the exact archive path apk.native_libs lists
        (lib/<abi>/<name>.so); anything else is rejected. Writes the library
        to the session artifact tree and answers with entry, abi, name, path,
        size, sha256, and artifact_id (register it once, then open path with
        the binary line). The interesting native logic in a modern app lived
        behind a full apktool decode before this; now a single lib comes out
        directly. There is no bytes, data or lib field.
        """
        return _dump(analysis.apk_extract_native_lib(session_id, entry))

    @tools.tool(name="apk.extract_file")
    def apk_extract_file(session_id: str, entry: str) -> dict[str, Any]:
        """Extract any one APK entry (asset, resource, dex, manifest) to a file.

        entry is the exact archive path apk.files lists; only an entry
        androguard already lists is accepted, so an arbitrary zip member or a
        path outside the archive is rejected. This is the general reader --
        apk.extract_native_lib is the .so-only specialisation. Writes the entry
        to the session artifact tree and answers with entry, name, category,
        path, size, sha256, and artifact_id (register it once, then open path).
        A bundled config, JS or hidden dex lived behind a full apktool decode
        before this. An entry over the capture cap is refused rather than
        written. There is no bytes, data or contents field.
        """
        return _dump(analysis.apk_extract_file(session_id, entry))

    @tools.tool(name="apk.classes")
    def apk_classes(
        session_id: str,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
    ) -> dict[str, Any]:
        """List internal (non-external) DEX classes with pagination.

        Answers with classes, count, total, offset, and has_more so a page
        that filled the limit is not read as the whole collected list.
        total is the number collected, capped at 10000; scan_capped is true
        when the real class count may be higher. has_more only means a
        larger offset still has collected rows.
        """
        return _dump(analysis.apk_classes(session_id, offset=offset, limit=limit))

    @tools.tool(name="apk.methods")
    def apk_methods(
        session_id: str,
        class_name: str,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
    ) -> dict[str, Any]:
        """List methods of a class (dotted or Lsmali/form; paginated).

        Answers with methods (name, descriptor, access), class_name, count,
        total, offset, and has_more so a page that filled the limit is not
        read as the whole collected class. total is the number collected,
        capped at 2000; scan_capped is true when more methods may exist.
        has_more only means a larger offset still has collected rows.
        """
        return _dump(
            analysis.apk_methods(session_id, class_name, offset=offset, limit=limit)
        )

    @tools.tool(name="apk.strings")
    def apk_strings(
        session_id: str,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=2000)] = 200,
        contains: str | None = None,
    ) -> dict[str, Any]:
        """List distinct DEX string constants with pagination.

        Answers with strings, count, total, offset, and has_more so a page
        that filled the limit is not read as the whole collected DEX. total
        is the number collected, capped at 5000; scan_capped is true when
        more unique strings may exist. has_more only means a larger offset
        still has collected rows. There is no items or constants field.

        Pass contains to hunt a substring (case-insensitive) -- a URL, a host,
        an api_key/token marker, a crypto constant -- across the DEX. The filter
        is applied during the scan, so the 5000 cap bounds matches, not the
        pre-filter set: a rare string is still found in an app with far more
        strings than the cap, where an unfiltered page would never reach it.
        When set the reply also carries filtered true and query (the term), and
        total/count/has_more describe the matched subset; scan_capped true then
        means still more matches may exist beyond the cap.
        """
        return _dump(
            analysis.apk_strings(session_id, offset=offset, limit=limit, contains=contains)
        )

    @tools.tool(name="apk.xrefs")
    def apk_xrefs(
        session_id: str,
        method_name: str,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
    ) -> dict[str, Any]:
        """List callers of every method named method_name.

        Answers with callers (class and method), method_name, count, and
        has_more so a page that filled the limit is not read as the whole list.
        """
        return _dump(analysis.apk_xrefs(session_id, method_name, limit=limit))

    @tools.tool(name="apk.decompile")
    def apk_decompile(
        session_id: str,
        class_name: str,
        timeout: Annotated[float, Field(gt=0, le=1800.0)] = 300.0,
    ) -> dict[str, Any]:
        """Decompile one class to Java via jadx (requires jadx + JRE).

        Answers with class_name, path and source, plus truncated when the
        Java was cut at the buffer. There is no java, code or text field.
        """
        return _dump(analysis.apk_decompile(session_id, class_name, timeout=timeout))

    @tools.tool(name="apk.decode")
    def apk_decode(
        session_id: str,
        timeout: Annotated[float, Field(gt=0, le=1800.0)] = 600.0,
        no_resources: bool = False,
    ) -> dict[str, Any]:
        """Decode the APK to smali and resources with apktool (editable tree).

        Answers with decoded_dir, manifest, smali_dirs, and has_resources.
        There is no output, path or tree field.
        """
        return _dump(analysis.apk_decode(session_id, timeout=timeout, no_resources=no_resources))

    @tools.tool(name="apk.repack")
    def apk_repack(
        session_id: str,
        decoded_dir: str = "",
        timeout: Annotated[float, Field(gt=0, le=1800.0)] = 600.0,
    ) -> dict[str, Any]:
        """Rebuild an APK from an apktool tree (defaults to this session's decode).

        Answers with apk, size, signed (false until apk.sign), and note.
        There is no output, path or repacked field. A successful rebuild is
        still unsigned.
        """
        return _dump(analysis.apk_repack(session_id, decoded_dir=decoded_dir, timeout=timeout))

    @tools.tool(name="apk.sign")
    def apk_sign(
        session_id: str,
        apk_path: str = "",
        keystore: str = "",
        keystore_password: str = "",
        key_alias: str = "",
        timeout: Annotated[float, Field(gt=0, le=1800.0)] = 300.0,
    ) -> dict[str, Any]:
        """Sign a rebuilt APK with apksigner (defaults to the Android debug keystore).

        Answers with apk, size, signed, keystore, and debug_keystore.
        signed is true only after apksigner verify succeeds. There is no
        output, path or signed_apk field.
        """
        return _dump(
            analysis.apk_sign(
                session_id,
                apk_path=apk_path,
                keystore=keystore,
                keystore_password=keystore_password,
                key_alias=key_alias,
                timeout=timeout,
            )
        )

    @tools.tool(name="apk.export_sources")
    def apk_export_sources(
        session_id: str,
        timeout: Annotated[float, Field(gt=0, le=1800.0)] = 300.0,
        no_imports: bool = False,
    ) -> dict[str, Any]:
        """Decompile the whole APK to a Java source tree via jadx.

        Answers with output_dir, sources_dir, java_file_count and java_files,
        plus has_more when the listed files were cut at the buffer. There is
        no files or sources field.
        """
        return _dump(
            analysis.apk_export_sources(session_id, timeout=timeout, no_imports=no_imports)
        )

    return tools.bindings
