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

    @tools.tool(name="apk.dex_headers")
    def apk_dex_headers(session_id: str) -> dict[str, Any]:
        """Report each classesN.dex header: version, id counts, multidex shape.

        The structural fingerprint a packer or unusual build leaves before any
        code is read, and the fast counterpart to apk.classes (which walks the
        parsed classes). Each DEX carries a fixed header with its format version
        (035/037/038/039 -- a version newer than the app's minSdk implies is a
        tell) and the sizes of its id pools. A single classes.dex with almost no
        classes next to a large encrypted asset is the classic dropper shape; an
        unexpected .dex count is the multidex / packer shape. Read straight from
        the DEX headers, so it stays cheap.

        Answers with dex_files (one entry per classesN.dex in archive order),
        dex_count, multidex, total_classes / total_methods / total_strings
        (summed over the valid headers) and has_more (the DEX cap was hit). Each
        entry carries name, version, valid (false when the blob is not a
        parseable DEX), checksum, declared_file_size, actual_size, and the id
        counts string_count / type_count / proto_count / field_count /
        method_count / class_def_count plus data_size.
        """
        return _dump(analysis.apk_dex_headers(session_id))

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

    @tools.tool(name="apk.disassemble")
    def apk_disassemble(
        session_id: str,
        class_name: str,
        method_name: str,
        descriptor: str | None = None,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=2000)] = 200,
    ) -> dict[str, Any]:
        """Decode one method's Dalvik (smali) bytecode.

        apk.method_info gives a method's signature and flags; this gives its
        body -- the actual instruction stream, read straight from androguard
        with no decompiler, so it answers even on a host with no jadx behind
        apk.decompile. Resolve the class (dotted ``com.x.Foo`` or ``Lcom/x/Foo;``
        form) and the method by name; when the name is overloaded, pass
        descriptor (the proto, e.g. ``(I)V``) to pick one, otherwise the first
        overload that has a body is used and ambiguous is set. A native or
        abstract method has no bytecode, reported has_code false.

        Answers with class_name, method_name, descriptor (the chosen overload),
        params, return_type, access, ambiguous, overloads (how many share the
        name), has_code, then instructions (paged), count, total, offset,
        has_more and scan_capped (the instruction cap was hit). Each instruction
        carries offset (byte offset within the code item), mnemonic (the Dalvik
        opcode, e.g. invoke-virtual), operands (the rendered args, with branch
        targets resolved against the offset), size (in bytes) and, when
        available, opcode (numeric) and hex (the raw encoding). A missing class
        or method is reported not_found; a session that is not an APK is refused
        target_mismatch.
        """
        return _dump(
            analysis.apk_disassemble(
                session_id,
                class_name,
                method_name,
                descriptor=descriptor,
                offset=offset,
                limit=limit,
            )
        )

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

    @tools.tool(name="apk.secrets")
    def apk_secrets(
        session_id: str,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=2000)] = 200,
    ) -> dict[str, Any]:
        """Find hard-coded credentials in the DEX string constants (pure Python).

        apk.strings lists every constant and apk.urls distils the network ones;
        this classifies each constant against a high-precision table of provider
        credentials -- the embedded-key triage that is one of the top findings in
        a mobile audit, since apps routinely ship AWS/Google/Firebase keys baked
        into the DEX. It shares its table and redaction with js.secrets: every
        pattern has a distinctive fixed prefix or structure (not "a long random
        string"), so false positives stay low, and each match is redacted in the
        output -- the provider-naming prefix and length kept, the middle masked --
        so a transcript never carries the live value. Kinds detected: AWS access
        key, Google API key and OAuth token, Firebase database URL, GitHub
        token/PAT, GitLab token, Slack token and webhook, Stripe
        secret/test/publishable keys, Twilio SID/key, SendGrid key, npm token,
        JWT and PEM private keys.

        Answers with findings (paged, sorted high severity first then kind),
        count, total, offset, has_more, a kinds tally (distinct findings per
        kind), total_findings (occurrences) and scan_capped (the DEX string pool
        hit its 5000-constant collection cap, so more may exist). Each finding
        carries kind, severity (high for a live/private credential, medium for a
        publishable/test/JWT one), preview (the redacted value), length (of the
        real secret) and count (occurrences); the DEX string pool has no line
        numbers, so the lines list is always empty. A clean app returns an empty
        findings list, not an error. This is a lexical scan over string
        constants: it will not catch a secret assembled at runtime, a key held
        only in resources.arsc, or a test/example key is still matched.

        A session that is not an APK is refused target_mismatch.
        """
        return _dump(analysis.apk_secrets(session_id, offset=offset, limit=limit))

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

    @tools.tool(name="apk.declared_permissions")
    def apk_declared_permissions(session_id: str) -> dict[str, Any]:
        """List the custom <permission>s the app declares, with protection level.

        apk.permissions lists what the app requests; this lists what it defines
        -- the custom permissions gating its own components. The security signal
        is protectionLevel: normal, dangerous, or left at the default can be held
        by any third-party app, so such a permission guarding an exported
        component is a privilege-escalation door (permission squatting).
        signature and above are safe.

        Answers with permissions, permission_groups, permission_trees, count,
        total, weak_count (how many permissions have a weak base) and has_more
        (a list hit its cap). Each permission carries name; protection_level (the
        decoded base: normal, dangerous, signature, signatureOrSystem, or unknown
        -- from the source name or the compiled AXML integer, defaulting to
        normal when absent); protection_flags (privileged, development, appop,
        ...); protection_level_raw (the literal, or null); permission_group;
        label; and weak_protection (true when the base is normal or dangerous).
        Each group/tree carries name and label. For requested permissions use
        apk.permissions.

        A session that is not an APK is refused target_mismatch.
        """
        return _dump(analysis.apk_declared_permissions(session_id))

    @tools.tool(name="apk.api_usage")
    def apk_api_usage(session_id: str) -> dict[str, Any]:
        """Scan the call graph for sensitive-API usage, grouped by threat category.

        The "what does this app actually do" view that follows apk.permissions
        and apk.urls. Where a permission only says an app *may* send SMS, this
        walks every external API the code invokes and, when it matches a curated
        table, counts the real call sites via that method's xref_from. Categories
        are reflection, dynamic_code (DexClassLoader and friends), process_exec
        (Runtime.exec/ProcessBuilder), native_load (System.loadLibrary), crypto
        (javax.crypto and java.security), sms (SmsManager), device_id
        (TelephonyManager identifiers), location, device_admin, accessibility,
        clipboard, installed_apps, record_audio and network.

        Answers with categories (only those with at least one real call site,
        ranked by total call sites), category_count, total_call_sites and
        scan_capped (the method scan hit its cap, so more may exist). Each
        category carries category, hits (total call sites), apis (the distinct
        APIs in it, ranked by callers), api_count and apis_truncated. Each api
        row carries class (dotted), method and callers. An API present in the
        analysis but never called is omitted -- a call site, not a mere ref, is
        what counts as usage.

        A session that is not an APK is refused target_mismatch.
        """
        return _dump(analysis.apk_api_usage(session_id))

    @tools.tool(name="apk.providers")
    def apk_providers(session_id: str) -> dict[str, Any]:
        """Report content providers as an attack surface: authorities and guards.

        A content provider is the widest data door an app can leave open, and
        the facts that decide whether it is safe are ones apk.components and
        apk.exported_components do not surface: the authorities that address it,
        whether it is exported, the read/write permissions guarding it, whether
        it hands out temporary URI grants, and any <path-permission> children
        that guard a sub-path differently. An exported provider with no
        permission is the classic leak (arbitrary read/write, SQL injection or
        path traversal into the app's data).

        Answers with providers, count, total, exported_unguarded (the headline:
        how many are effectively exported yet carry no permission) and has_more.
        Each provider carries name, authorities (the android:authorities list,
        split on ;), exported (the literal android:exported, or null when
        absent), effective_exported (the resolved value -- when android:exported
        is absent the default is true only for targetSdk < 17 and an authority
        exists), enabled, permission, read_permission, write_permission,
        grant_uri_permissions (true when android:grantUriPermissions is set or a
        <grant-uri-permission> exists), grant_uris (each with path/path_prefix/
        path_pattern), path_permissions (each with those plus its own
        permission/read_permission/write_permission) and guarded (any permission
        is set).

        A session that is not an APK is refused target_mismatch.
        """
        return _dump(analysis.apk_providers(session_id))

    @tools.tool(name="apk.native_methods")
    def apk_native_methods(
        session_id: str,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=2000)] = 100,
    ) -> dict[str, Any]:
        """Enumerate the app's JNI native methods -- the boundary into the .so files.

        A method declared native has no bytecode: its body lives in a shared
        library, reached over JNI. apk.method_info decodes that flag one method
        at a time; this sweeps the whole DEX and lists every native method, so an
        analyst who found nothing in the bytecode knows exactly which exports to
        chase in apk.native_libs.

        Answers with native_methods (paged, sorted by class then method), count,
        total, offset, has_more and scan_capped (the sweep hit its collection
        cap). Each row carries class (dotted), method, descriptor (the raw
        Dalvik proto), params, return_type and jni_symbol -- the C symbol JNI
        resolves the method to, in its short (non-overloaded) mangling, so it is
        the string to grep for in the .so. An overloaded native method's real
        export carries an extra argument-type suffix this does not add.

        A session that is not an APK is refused target_mismatch.
        """
        return _dump(analysis.apk_native_methods(session_id, offset=offset, limit=limit))

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
