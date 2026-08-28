"""Protocol-independent apk.* tool definitions (Android static analysis)."""

from __future__ import annotations

from typing import Annotated, Any, Literal

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
        signature_files, and has_more so a list that filled the cap is not read
        as every signer. Signing scheme is reported as v1_signed, v2_signed and
        v3_signed, plus signing_schemes (e.g. ["v2","v3"]): v1 is the tamperable
        per-entry JAR signature, v2/v3 hash the whole APK. There is no certs or
        signatures field.
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

    @tools.tool(name="apk.extract_native_lib")
    def apk_extract_native_lib(session_id: str, name: str) -> dict[str, Any]:
        """Extract one embedded native library to a file the native tools can open.

        apk.native_libs lists the .so files an app ships but could not hand one
        off: jadx and apktool only touch Java/smali, so an app's crypto, DRM or
        anti-tamper logic (which lives in native code) was a dead end. This pulls
        the exact bytes of a lib/<abi>/<name>.so entry to disk so a follow-up
        native session (session.create on the returned path) can analyze it with
        r2.* or ghidra.* -- the seam from the Android line to the native line.
        Pass name exactly as apk.native_libs reports it. Answers with name, abi,
        path, size, sha256 and artifact_id (the registered handle). A name that
        is not a real .so entry in the archive is refused (not_found or
        invalid_params), so this is not an arbitrary zip extractor.
        """
        return _dump(analysis.apk_extract_native_lib(session_id, name))

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

    @tools.tool(name="apk.class_summary")
    def apk_class_summary(session_id: str, class_name: str) -> dict[str, Any]:
        """A class header at a glance: superclass, interfaces, access and counts.

        apk.classes lists names and apk.methods/apk.fields enumerate members; this
        places one class in the app without paging either list. Resolve by
        class_name (dotted com.example.App or Lsmali/form). Answers with class_name
        (smali), superclass and interfaces (smali descriptors, interfaces a list),
        access (the flag string, e.g. "public abstract"), method_count and
        field_count, plus is_external for a class only referenced, not defined, in
        the DEX. It is the Android analogue of reading a type's header before its
        members. A class the DEX does not carry is a clean not_found.
        """
        return _dump(analysis.apk_class_summary(session_id, class_name))

    @tools.tool(name="apk.subclasses")
    def apk_subclasses(
        session_id: str,
        class_name: str,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
    ) -> dict[str, Any]:
        """The inverse of apk.class_summary: who extends a class / implements an interface.

        class_summary reads one class's own superclass and interfaces (the "up"
        edges); this is the "down" direction type-graph navigation needs. Given a
        class or interface (dotted com.example.Base or Lsmali/form), it scans the
        DEX for every defined class that names the target as its superclass or
        among its interfaces -- the way to answer "every Activity/Service
        subclass", "every implementer of this callback/crypto interface", "every
        subclass of this obfuscated base". The target need not be defined in the
        DEX (a framework class like android.app.Activity is the common case), so
        this never returns not_found; target_defined reports whether the DEX
        itself carries it.

        Answers with subtypes -- a merged list of {class_name, relation} where
        relation is extends (a direct subclass) or implements (an interface
        implementer), sorted by class name -- plus count, total, offset and
        has_more for paging, subclass_count and implementer_count (totals before
        paging), target (the resolved smali form) and scan_capped (set once the
        class scan hit its 10000 ceiling). The list field is subtypes (there is no
        classes or results field). Only direct subtypes are reported, not the full
        transitive tree; walk it again on a result to go deeper.
        """
        return _dump(
            analysis.apk_subclasses(session_id, class_name, offset=offset, limit=limit)
        )

    @tools.tool(name="apk.class_xrefs")
    def apk_class_xrefs(
        session_id: str,
        class_name: str,
        direction: str = "from",
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
    ) -> dict[str, Any]:
        """Class-level cross references: who uses a class, or what a class uses.

        apk.xrefs walks the call graph by method name and apk.subclasses walks
        the inheritance tree; this is the type usage edge neither shows.
        direction="from" (the default) answers who references the class -- every
        site that instantiates it (REF_NEW_INSTANCE), names it (REF_CLASS_USAGE)
        or invokes one of its methods -- the way to find where an obfuscated or
        crypto class is actually put to work. direction="to" answers what classes
        this class depends on. The target need not be defined in the DEX: a
        framework type like javax.crypto.Cipher still has inbound edges, so "who
        uses Cipher" resolves. Resolve by class_name (dotted com.example.Foo or
        Lsmali/form); a name the DEX neither defines nor references is a clean
        not_found.

        Answers with xrefs -- edges of {class, method, kind, offset}, where class
        is the class at the other end, method the method carrying the reference,
        kind the androguard REF_TYPE name (REF_NEW_INSTANCE, REF_CLASS_USAGE,
        INVOKE_VIRTUAL, ...) and offset the bytecode offset -- deduplicated and
        sorted, plus count, total, offset and has_more for paging, target (the
        resolved smali form), direction and scan_capped (set once the 20000-edge
        ceiling was hit). The list field is xrefs, not results.
        """
        return _dump(
            analysis.apk_class_xrefs(
                session_id,
                class_name,
                direction=direction,
                offset=offset,
                limit=limit,
            )
        )

    @tools.tool(name="apk.methods")
    def apk_methods(
        session_id: str,
        class_name: str,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
        name_contains: str = "",
        access: str = "",
    ) -> dict[str, Any]:
        """List methods of a class (dotted or Lsmali/form; paginated, filterable).

        Answers with methods (name, descriptor, access), class_name, count,
        total, offset, and has_more so a page that filled the limit is not
        read as the whole collected class. scan_capped is true when the scan
        stopped before examining every method (bounded at 2000 scanned).
        has_more only means a larger offset still has collected rows.

        On a large class, narrow instead of paging: name_contains is a
        case-insensitive substring of the method name, and access a
        case-insensitive substring of the access-flag string -- pass native to
        find the JNI bridges into a .so, or public/static/abstract to slice by
        modifier. When a filter is set the reply echoes it as filter and total
        becomes the number of matches (so offset/has_more page the matches).
        """
        return _dump(
            analysis.apk_methods(
                session_id,
                class_name,
                offset=offset,
                limit=limit,
                name_contains=name_contains,
                access=access,
            )
        )

    @tools.tool(name="apk.fields")
    def apk_fields(
        session_id: str,
        class_name: str,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
        name_contains: str = "",
        access: str = "",
    ) -> dict[str, Any]:
        """List a class's declared fields (dotted or Lsmali/form; paginated, filterable).

        The read surface lists a class's methods (apk.methods) but had no way to
        list its fields, though a field is where a key, token, URL or feature flag
        usually lives -- and apk.field_xrefs needs an exact field name to pivot on.
        Answers with fields (name, type, access), class_name, count, total, offset,
        and has_more so a page that filled the limit is not read as the whole
        class. type is the raw Dalvik type descriptor (I for int,
        Ljava/lang/String; for a String). scan_capped is true when the scan
        stopped early. has_more only means a larger offset still has collected
        rows. Pair with apk.field_xrefs: list here, then pivot on a name to its
        read/write sites.

        Narrow the same way as apk.methods: name_contains is a case-insensitive
        substring of the field name and access a case-insensitive substring of the
        access-flag string (static, private, final). When a filter is set the
        reply echoes it as filter and total becomes the number of matches.
        """
        return _dump(
            analysis.apk_fields(
                session_id,
                class_name,
                offset=offset,
                limit=limit,
                name_contains=name_contains,
                access=access,
            )
        )

    @tools.tool(name="apk.method_bytecode")
    def apk_method_bytecode(
        session_id: str,
        class_name: str,
        method_name: str,
        descriptor: str = "",
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=2000)] = 200,
    ) -> dict[str, Any]:
        """Disassemble one method's Dalvik bytecode (the Android r2.disasm_function).

        apk.methods lists a class's methods but not what any does; jadx/apktool
        decompile the whole app and need those tools installed. This shows just
        one routine's instructions -- for a license check, a crypto call, an
        anti-tamper guard. Resolve by class_name (dotted or Lsmali/form) plus
        method_name; pass descriptor (e.g. "(I)Z") to pick one overload, else the
        first is used and overloads reports how many share the name. Answers with
        class_name, method, descriptor, access, has_code, instructions, count,
        total, offset and has_more. Each instruction carries addr (bytes into the
        method code), mnemonic, operands (with the invoked method or referenced
        field/string named, not an index), bytes and size -- so a call reads as
        its target. An abstract/native method has has_code false and no
        instructions; insns_capped means a huge method was cut at 100000.
        """
        return _dump(
            analysis.apk_method_bytecode(
                session_id,
                class_name,
                method_name,
                descriptor=descriptor,
                offset=offset,
                limit=limit,
            )
        )

    @tools.tool(name="apk.method_refs")
    def apk_method_refs(
        session_id: str,
        class_name: str,
        method_name: str,
        descriptor: str = "",
    ) -> dict[str, Any]:
        """Summarise what one method touches: calls, fields and strings.

        Where apk.method_bytecode returns every instruction, this abstracts the
        triage question -- what does this routine call, which fields does it read
        or write, which string constants does it load -- into three deduplicated
        lists, the static-Dalvik analogue of a native function's call and data
        references. Resolve by class_name (dotted or Lsmali/form) plus method_name;
        pass descriptor (e.g. "(I)Z") to pin one overload, else the first is used
        and overloads reports how many share the name. Answers with class_name,
        method, descriptor, access, has_code and: calls (each target
        Lpkg/Cls;->m(...)ret with its call-site count), fields (each field with
        reads and writes counts, so a flag flipped once stands out from one only
        read) and strings (each loaded constant with its occurrence count -- an
        embedded URL, key or error message). Lists are sorted. An abstract/native
        method has has_code false and empty lists; calls_truncated / fields_truncated
        / strings_truncated mark a method whose unique set exceeded 4096.
        """
        return _dump(
            analysis.apk_method_refs(
                session_id,
                class_name,
                method_name,
                descriptor=descriptor,
            )
        )

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
        direction: Literal["callers", "callees"] = "callers",
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
    ) -> dict[str, Any]:
        """List callers or callees of every method named method_name.

        direction "callers" (default) lists who calls the method; direction
        "callees" lists what the method calls (framework APIs included), so a
        call graph can be walked forward as well as backward. Answers with
        method_name, direction, count, has_more (so a page that filled the limit
        is not read as the whole list), and one list of {class, method} named
        after the direction: callers for "callers", callees for "callees". There
        is no callers key on a callees answer, or vice versa.
        """
        return _dump(
            analysis.apk_xrefs(session_id, method_name, direction=direction, limit=limit)
        )

    @tools.tool(name="apk.string_xrefs")
    def apk_string_xrefs(
        session_id: str,
        value: str,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
    ) -> dict[str, Any]:
        """List methods that reference an exact string constant.

        Pivots from a constant an agent found in apk.strings (a URL, a key, an
        error message) to the code that uses it. Answers with value, found,
        xrefs (each {class, method}), count, total, offset, has_more and
        scan_capped. found is False when the string is absent and True with an
        empty xrefs when it is present but unreferenced, so the two cases do not
        look alike; scan_capped means the search stopped before every string was
        examined. The match is exact, not a substring search.
        """
        return _dump(
            analysis.apk_string_xrefs(session_id, value, offset=offset, limit=limit)
        )

    @tools.tool(name="apk.field_xrefs")
    def apk_field_xrefs(
        session_id: str,
        field_name: str,
        direction: Literal["read", "write"] = "read",
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
    ) -> dict[str, Any]:
        """List methods that read or write a field, matched by exact name.

        Fields hold keys, tokens and config, so who sets one and who uses it are
        different questions: direction "read" (default) lists methods that read
        the field, direction "write" lists methods that write it. A field name
        can recur across classes, so every field with the name contributes and
        the edges are merged. Answers with field_name, direction, found, xrefs
        (each {class, method}), count, total, offset, has_more and scan_capped.
        found is False for an absent field and True with an empty xrefs for one
        present but untouched in that direction, so the two do not look alike.
        The match is exact, not a substring search.
        """
        return _dump(
            analysis.apk_field_xrefs(
                session_id, field_name, direction=direction, offset=offset, limit=limit
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
