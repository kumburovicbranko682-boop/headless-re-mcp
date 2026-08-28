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

    @tools.tool(name="apk.security")
    def apk_security(session_id: str) -> dict[str, Any]:
        """Report the <application> element's security posture.

        The reviewer's first look. Answers with package, debuggable,
        allow_backup, uses_cleartext_traffic, network_security_config,
        application_class (a custom android.app.Application subclass, where a
        packer/loader often runs first), min_sdk and target_sdk. A boolean the
        manifest never declared is null ("not set"), which is not the same as
        false -- so the caller can apply the target SDK's own default rather
        than assume one. network_security_config and application_class are the
        declared names or null. There is no flags or manifest field; use
        apk.manifest for the raw XML.
        """
        return _dump(analysis.apk_security(session_id))

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

    @tools.tool(name="apk.intent_filters")
    def apk_intent_filters(session_id: str) -> dict[str, Any]:
        """Map each component's <intent-filter> -- the app's declared entry points.

        Where apk.components lists names, this shows how the outside world
        reaches them. Answers with components (only those that declare a
        filter), count, total and has_more. Each component carries type
        (activity, service or receiver), name, exported (true/false, or null
        when the attribute is absent and the platform default applies), actions
        and categories (the android:name lists), data (a list of
        scheme/host/port/path/mimeType filter dicts), schemes (the distinct
        url schemes), deep_link (true when any scheme is present) and has_more
        (that component's action/category list was capped). An exported
        component with a custom-scheme or MAIN/LAUNCHER filter is the entry
        point to inspect first.
        """
        return _dump(analysis.apk_intent_filters(session_id))

    @tools.tool(name="apk.meta_data")
    def apk_meta_data(session_id: str) -> dict[str, Any]:
        """Lift every <meta-data> element from the manifest (keys, SDK markers).

        meta-data is where apps stash API keys and framework switches the
        runtime reads: Maps/Firebase keys, SDK app ids, feature toggles. Answers
        with meta_data (a list of entries), count, total and has_more. Each entry
        carries name, value (the literal android:value) and resource (an
        android:resource @id, when it points at a resource rather than a
        literal), plus scope (the enclosing element: application, activity,
        service, receiver or provider) and scope_name (that component's name) so
        a key scoped to one exported activity is not read as app-wide. A field
        the element did not declare is null. Read has_more: a very large manifest
        is capped.
        """
        return _dump(analysis.apk_meta_data(session_id))

    @tools.tool(name="apk.files")
    def apk_files(
        session_id: str,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=2000)] = 200,
    ) -> dict[str, Any]:
        """List every archive entry (the whole zip), bucketed, with sizes.

        Where apk.native_libs sees only lib/, this walks the full archive.
        Answers with files (each name, category and size), count, total, offset,
        has_more, categories (a category->count map) and total_uncompressed.
        category is one of manifest, arsc, signature, dex, native_lib, resource,
        asset, kotlin or other -- so a multidex app or an embedded jar/apk under
        assets/ is visible at a glance. size is the uncompressed byte size when
        androguard exposes the central directory, else null (never read by
        inflating the entry). scan_capped marks a pathological archive whose
        entry count hit the collect cap. Read has_more so a page that filled the
        limit is not read as every entry.
        """
        return _dump(analysis.apk_files(session_id, offset=offset, limit=limit))

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

    @tools.tool(name="apk.method_info")
    def apk_method_info(
        session_id: str,
        class_name: str,
        method_name: str,
    ) -> dict[str, Any]:
        """Resolve one method's signature and decode its access flags.

        apk.methods lists a class's methods with raw descriptor and access
        strings; this parses one method (class dotted or Lsmali/form) into
        typed parameters and a return type, and decodes the flags into
        booleans. All overloads of the name are returned. A native method
        whose has_code is false is the JNI bridge worth chasing into
        apk.native_libs.

        Answers with class_name, method_name, methods, count and scan_capped.
        Each methods row carries descriptor, params (human types, e.g.
        java.lang.String, byte[]), return_type, signature_parsed (false when
        the proto could not be walked, leaving descriptor authoritative),
        access (the raw flag string), flags (its tokens) and booleans
        is_public/is_private/is_protected/is_static/is_final/is_synchronized/
        is_native/is_abstract/is_synthetic/is_varargs/is_constructor plus
        has_code (false for native or abstract methods).

        A missing class or method is reported not_found; a session that is not
        an APK is refused target_mismatch.
        """
        return _dump(analysis.apk_method_info(session_id, class_name, method_name))

    @tools.tool(name="apk.class_info")
    def apk_class_info(
        session_id: str,
        class_name: str,
    ) -> dict[str, Any]:
        """Report a class's superclass, interfaces, access flags and fields.

        apk.methods/apk.method_info cover behaviour; this covers shape (class
        dotted or Lsmali/form). A class extending a known base or implementing
        Parcelable/Serializable/Runnable is a fast structural tell, and the
        declared fields often name the keys, URLs and config a class holds.

        Answers with class_name, superclass (human type, or null for
        java.lang.Object-less roots), interfaces (human types),
        interfaces_truncated, access (raw flag string), the class booleans
        flags/is_public/is_final/is_abstract/is_interface/is_enum/is_annotation/
        is_synthetic, fields, field_count, fields_truncated, method_count and
        external (true when the class is a referenced-but-not-defined type, so
        its fields and method_count read as empty). Each fields row carries name,
        type (human, e.g. java.lang.String, byte[]), descriptor (raw), access and
        the field booleans is_public/is_private/is_protected/is_static/is_final/
        is_volatile/is_transient/is_enum/is_synthetic.

        A missing class is reported not_found; a session that is not an APK is
        refused target_mismatch.
        """
        return _dump(analysis.apk_class_info(session_id, class_name))

    @tools.tool(name="apk.exported_components")
    def apk_exported_components(session_id: str) -> dict[str, Any]:
        """Fold the four component types into the externally-reachable surface.

        apk.components lists names and apk.intent_filters lists filters; this
        answers the security question they only imply: which activities,
        services, receivers and providers another app can invoke, and which of
        those lack a permission guard. A component counts as exported when
        android:exported is true, or -- when the attribute is absent -- when it
        declares an intent-filter (the platform default), flagged
        exported_implied.

        Answers with components (only the effectively-exported ones), count,
        exported_total, total_components (all scanned), unguarded_count (exported
        with no permission -- the ones to look at first) and has_more. Each
        component carries type (activity/service/receiver/provider), name,
        exported (the explicit attribute: true/false, or null when absent),
        effective_exported (always true here), exported_implied (true when it
        came from an intent-filter, not an explicit attribute), has_intent_filter,
        permission, read_permission, write_permission (the provider read/write
        guards, else null), guarded (any permission is set), launcher (a
        MAIN/LAUNCHER entry) and deep_link with schemes (custom-scheme handlers).
        An unguarded exported component is the classic Android attack surface.

        A session that is not an APK is refused target_mismatch.
        """
        return _dump(analysis.apk_exported_components(session_id))

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

    @tools.tool(name="apk.urls")
    def apk_urls(
        session_id: str,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=2000)] = 200,
    ) -> dict[str, Any]:
        """Extract network indicators (URLs, hosts, IPs) from DEX string constants.

        apk.strings lists every constant; this distils the network-relevant ones
        -- the C2 endpoints, API bases, tracking beacons and hard-coded IPs a
        triage wants first -- into a deduped, classified inventory. URLs are
        matched for the http/https/ws/wss/ftp schemes, trimmed of trailing
        punctuation, and split into scheme and host.

        Answers with urls (paged, sorted), count, total, offset and has_more;
        hosts (a per-host tally ranked by how many distinct URLs point at it) with
        host_count and hosts_truncated; ips (distinct bare IPv4 literals) with
        ip_count; and scan_capped (the DEX string pool or an inventory hit its
        collection cap, so more may exist). Each url row carries url, scheme and
        host. Bare IPv4 matching is best-effort and can also catch version-like
        numbers, so treat ips as leads, not proof.

        A session that is not an APK is refused target_mismatch.
        """
        return _dump(analysis.apk_urls(session_id, offset=offset, limit=limit))

    @tools.tool(name="apk.uses_features")
    def apk_uses_features(session_id: str) -> dict[str, Any]:
        """Report the hardware/software features and libraries the app declares.

        The capability profile a reviewer reads before the code: <uses-feature>
        says what the app expects the device to have (camera, telephony, GPS,
        fingerprint, a GL ES level), and <uses-library>/<uses-native-library>
        name the platform and vendor libraries it links against.

        Answers with features, feature_count, feature_total; libraries,
        library_count, library_total; and has_more (either list hit its cap).
        Each feature carries name, required and gl_es_version (the android:
        glEsVersion literal, or null). Each library carries name, required and
        native (true for <uses-native-library>). required is the android:required
        attribute, defaulting to true when absent -- required=false marks a
        capability the app can run without, the pattern an app uses to broaden
        its install base while still using a sensitive feature when present.

        A session that is not an APK is refused target_mismatch.
        """
        return _dump(analysis.apk_uses_features(session_id))

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
