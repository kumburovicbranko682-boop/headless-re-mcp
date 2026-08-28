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
        version, sdk or abis field. A zip with no readable package name is a
        backend error, not an opened package.
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

    @tools.tool(name="apk.summary")
    def apk_summary(session_id: str) -> dict[str, Any]:
        """Profile an APK in one call -- its identity and shape at a glance.

        The Android counterpart to wasm.summary and js.summary: it rolls the
        manifest-level facts that apk.open, apk.components, apk.permissions,
        apk.certificates and apk.native_libs each return -- five calls -- into
        one, using the cheap manifest parse so it skips the expensive DEX
        analysis the class/string/xref tools need. Answers with opened,
        package, version_name, version_code, min_sdk, target_sdk,
        main_activity, permission_count, components (the activities, services,
        receivers and providers counts, not their names -- use apk.components
        for those), native_abis, native_lib_count, certificate_count and
        v1_signed. It reports counts, not lists; reach for the per-aspect tool
        when a full listing is needed. A zip with no readable package name is a
        backend error, not an opened package.
        """
        return _dump(analysis.apk_summary(session_id))

    @tools.tool(name="apk.exported_components")
    def apk_exported_components(
        session_id: str,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
    ) -> dict[str, Any]:
        """List the components other apps can reach (the Android attack surface).

        The security lens apk.components lacks: where that lists every
        component name, this walks AndroidManifest.xml and reports only the
        activities, activity-aliases, services, receivers and providers that
        resolve to exported -- the entry points another app or the shell can
        invoke, and the first place to look for an unguarded launch, a
        SQL-injectable provider or a broadcast that leaks state. A component
        counts as exported when android:exported="true"; when the attribute is
        unset, an activity/service/receiver is exported if it declares an
        intent-filter and a provider by the API-17 default (exported below a
        target SDK of 17, private at or above it). Manifest-level, so it needs
        no DEX analysis. Each row is name (fully qualified), type, permission
        (the android:permission guarding it, or null -- an exported component
        behind a signature permission is far less exposed), exported_declared
        (the raw "true"/"false" or null so an inferred verdict is auditable)
        and has_intent_filter. Answers with exported, counts (the exported
        total per type), count, total, offset and has_more so a filled page is
        not read as the whole surface; total is capped at 2000 with scan_capped
        when more may exist, and truncated is true when the manifest XML could
        not be parsed.
        """
        return _dump(analysis.apk_exported_components(session_id, offset=offset, limit=limit))

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
        return _dump(analysis.apk_methods(session_id, class_name, offset=offset, limit=limit))

    @tools.tool(name="apk.strings")
    def apk_strings(
        session_id: str,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=2000)] = 200,
    ) -> dict[str, Any]:
        """List distinct DEX string constants with pagination.

        Answers with strings, count, total, offset, and has_more so a page
        that filled the limit is not read as the whole collected DEX. total
        is the number collected, capped at 5000; scan_capped is true when
        more unique strings may exist. has_more only means a larger offset
        still has collected rows. There is no items or constants field.
        """
        return _dump(analysis.apk_strings(session_id, offset=offset, limit=limit))

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

    @tools.tool(name="apk.callees")
    def apk_callees(
        session_id: str,
        method_name: str,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
    ) -> dict[str, Any]:
        """List the methods that every method named method_name calls.

        The forward direction of apk.xrefs: xrefs answers who calls this method,
        callees answers what this method calls -- the outgoing edges of the
        static call graph, into both framework and app code.
        Answers with callees (class and method), method_name, count, and
        has_more so a page that filled the limit is not read as the whole list.
        There is no callers field here.
        """
        return _dump(analysis.apk_callees(session_id, method_name, limit=limit))

    @tools.tool(name="apk.string_xrefs")
    def apk_string_xrefs(
        session_id: str,
        value: str,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
    ) -> dict[str, Any]:
        """List the methods that reference a given DEX string constant.

        The pivot from a string to code: given a value found via apk.strings
        (a URL, a crypto constant, an error message, a secret), this reports
        every method that loads that exact string -- "who uses this". The
        value is matched byte for byte and never trimmed, so surrounding
        whitespace is significant. Answers with referrers (class and method),
        the echoed value, found (true when the string exists in the module at
        all, so an unreferenced string reads apart from a string that is not
        present), count, and has_more so a page that filled the limit is not
        read as the whole list. There is no callers or callees field here.
        """
        return _dump(analysis.apk_string_xrefs(session_id, value, limit=limit))

    @tools.tool(name="apk.field_xrefs")
    def apk_field_xrefs(
        session_id: str,
        field_name: str,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
    ) -> dict[str, Any]:
        """List the methods that read or write a given field.

        The field counterpart of apk.xrefs: name a field and this reports every
        method that reads or writes it -- how state (a token, a flag, a
        singleton) flows through the app. Field names are not unique across
        classes, so the name is matched across the whole module and every row
        names the field's declaring class. Answers with accesses (each row is
        class and method of the accessing code, kind read or write, and
        field_class the class that declares the field), field_name, matched
        _fields (how many distinct fields the name resolved to), found (true
        when the name matched any field, so an unaccessed field reads apart
        from an absent one), count, and has_more so a page that filled the
        limit is not read as the whole list. There is no callers or callees
        field here.
        """
        return _dump(analysis.apk_field_xrefs(session_id, field_name, limit=limit))

    @tools.tool(name="apk.decompile")
    def apk_decompile(
        session_id: str,
        class_name: str,
        timeout: Annotated[float, Field(gt=0, le=1800.0)] = 300.0,
    ) -> dict[str, Any]:
        """Decompile one class to Java via jadx (requires jadx + JRE).

        Answers with class_name, path and source, plus truncated when the
        Java was cut at the buffer. There is no java, code or text field. If
        jadx exited non-zero on the whole-APK pass but still wrote this class,
        the reply carries exit_code, tool_failed and stderr so a partial
        decompile is not read as complete.
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
        still unsigned. An empty or non-zip output (apktool can exit 0 yet
        leave a truncated file) is reported as backend_error, not as a rebuilt
        apk, so an unusable file never reaches apk.sign.
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
        no files or sources field. If jadx exited non-zero but still wrote a
        tree, the reply carries exit_code, tool_failed and stderr so a tree
        that is missing classes is not read as a complete decompile.
        """
        return _dump(
            analysis.apk_export_sources(session_id, timeout=timeout, no_imports=no_imports)
        )

    return tools.bindings
