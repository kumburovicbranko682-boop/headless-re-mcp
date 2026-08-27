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
        was cut at the buffer. A cut manifest is not well-formed XML, so when
        truncated the whole document is written to manifest_path (registered as
        artifact_id) and can be read back in full; a manifest within the buffer
        has neither.
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
        """List signing certificates and v1 signature files.

        Answers with certificates (subject, issuer, serial, sha256),
        signature_files, v1_signed, and has_more so a list that filled the
        cap is not read as every signer. There is no certs or signatures field.
        """
        return _dump(analysis.apk_certificates(session_id))

    @tools.tool(name="apk.components")
    def apk_components(session_id: str) -> dict[str, Any]:
        """List activities, services, receivers, and providers.

        Answers with activities, services, receivers, providers,
        main_activity, and has_more so a list that filled the cap is not
        read as every component. There is no components field.
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

    @tools.tool(name="apk.classes")
    def apk_classes(
        session_id: str,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
        name_filter: str = "",
    ) -> dict[str, Any]:
        """List internal (non-external) DEX classes with pagination.

        Answers with classes, count, total, offset, and has_more so a page
        that filled the limit is not read as the whole collected list.
        total is the number collected, capped at 10000; scan_capped is true
        when the real class count may be higher. has_more only means a
        larger offset still has collected rows. name_filter keeps only
        classes whose name contains that substring (case-sensitive), applied
        during the scan before the cap, so a target class in a >10000-class
        app is findable rather than stranded past the collect boundary.
        """
        return _dump(
            analysis.apk_classes(session_id, offset=offset, limit=limit, name_filter=name_filter)
        )

    @tools.tool(name="apk.methods")
    def apk_methods(
        session_id: str,
        class_name: str,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
        name_filter: str = "",
    ) -> dict[str, Any]:
        """List methods of a class (dotted or Lsmali/form; paginated).

        Answers with methods (name, descriptor, access), class_name, count,
        total, offset, and has_more so a page that filled the limit is not
        read as the whole collected class. total is the number collected,
        capped at 2000; scan_capped is true when more methods may exist.
        has_more only means a larger offset still has collected rows.
        name_filter keeps only methods whose name contains that substring
        (case-sensitive), applied during the scan before the cap.
        """
        return _dump(
            analysis.apk_methods(
                session_id, class_name, offset=offset, limit=limit, name_filter=name_filter
            )
        )

    @tools.tool(name="apk.strings")
    def apk_strings(
        session_id: str,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=2000)] = 200,
        name_filter: str = "",
    ) -> dict[str, Any]:
        """List distinct DEX string constants with pagination.

        Answers with strings, count, total, offset, and has_more so a page
        that filled the limit is not read as the whole collected DEX. total
        is the number collected, capped at 5000; scan_capped is true when
        more unique strings may exist. has_more only means a larger offset
        still has collected rows. There is no items or constants field.
        name_filter keeps only strings containing that substring
        (case-sensitive), applied during the scan before the cap, so a
        URL/domain/key fragment in a >5000-string app is findable rather
        than stranded past the collect boundary.
        """
        return _dump(
            analysis.apk_strings(session_id, offset=offset, limit=limit, name_filter=name_filter)
        )

    @tools.tool(name="apk.xrefs")
    def apk_xrefs(
        session_id: str,
        method_name: str,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
        class_name: str = "",
    ) -> dict[str, Any]:
        """List callers of a method named method_name.

        Answers with callers (class and method), method_name, class_name, count,
        total, offset, and has_more so a page that filled the limit is not read as
        the whole list, plus scan_capped when the caller collection hit its ceiling
        (total is then the capped count, not every call site on the device).
        class_name (dotted or Lsmali/ form) scopes the search to one declaring
        class; without it every method sharing the name is unioned, which in an
        obfuscated app (a/b/c) or for a common name (run, decrypt) conflates
        unrelated callers and can blow the collect cap. class_name in the answer
        echoes the scope (null when unscoped).
        """
        return _dump(
            analysis.apk_xrefs(
                session_id, method_name, offset=offset, limit=limit, class_name=class_name
            )
        )

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
