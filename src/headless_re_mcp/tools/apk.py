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
        was cut -- by the character cap or, on a quote-heavy manifest, by the
        result-size budget, so treat manifest_xml as possibly partial and read
        truncated rather than assuming the whole document is present. Also
        surfaces the <application> security flags debuggable, allow_backup,
        and uses_cleartext_traffic as booleans, or null when the attribute is
        not declared (null is not False: an unset allow_backup still defaults
        to backups enabled on pre-Android-12 targets, and an unset
        uses_cleartext_traffic defaults to allowing plaintext HTTP below
        target API 28). network_security_config is the declared
        Network Security Config resource reference (or null) -- its presence
        means cleartext and CA-trust are governed by that config, which
        qualifies the cleartext flag.
        """
        return _dump(analysis.apk_manifest(session_id))

    @tools.tool(name="apk.permissions")
    def apk_permissions(session_id: str) -> dict[str, Any]:
        """List requested permissions, their protection levels, and dangerous ones.

        Answers with permissions and requested_permissions (the uses-permission
        names), count, and has_more so a list that filled the cap is not read as
        every permission. There is no declared or requested field.
        protection_levels maps a requested permission to its base protection
        level ("normal", "dangerous", "signature" ...) for those androguard can
        resolve from the platform DB or the APK's own <permission> declarations;
        a permission absent from the map is simply unresolved, not necessarily
        safe. dangerous is the subset of requested permissions whose level is
        dangerous -- the runtime-consent attack surface (contacts, location, SMS,
        mic ...). custom_permissions lists the permissions the app itself defines
        via <permission>, distinct from the ones it requests.
        """
        return _dump(analysis.apk_permissions(session_id))

    @tools.tool(name="apk.certificates")
    def apk_certificates(session_id: str) -> dict[str, Any]:
        """List signing certificates and the signature schemes that signed the APK.

        Answers with certificates (subject, issuer, serial, sha256, and
        not_before/not_after as ISO-8601 validity bounds or null when a cert
        shape omits them), signature_files, and has_more so a list that filled
        the cap is not read as every signer. Signing-scheme flags v1_signed, v2_signed, v3_signed,
        and the overall signed report which APK Signature Schemes are present:
        each is true/false, or null when this androguard build could not
        determine it (null is not "unsigned"). v1-only signing on a modern APK
        is the CVE-2017-13156 (Janus) risk pattern. There is no certs or
        signatures field.
        """
        return _dump(analysis.apk_certificates(session_id))

    @tools.tool(name="apk.components")
    def apk_components(session_id: str) -> dict[str, Any]:
        """List activities, services, receivers, and providers.

        Answers with activities, services, receivers, providers,
        main_activity, and has_more so a list that filled the cap is not
        read as every component. There is no components field. exported
        groups the subset of those components reachable by other apps
        (activities, services, receivers, providers) -- the app's attack
        surface: a component is exported when android:exported="true", or
        when it declares an intent-filter and does not set exported="false"
        (the pre-Android-12 implicit-export rule). The rare legacy case of an
        unset provider defaulting to exported on targetSdk < 17 is not
        inferred, so an exported provider without android:exported may be
        under-reported.
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
    ) -> dict[str, Any]:
        """List internal (non-external) DEX classes with pagination.

        Answers with classes, count, total, offset, and has_more so a page
        that filled the limit is not read as the whole collected list.
        total is the number collected, capped at 10000; scan_capped is true
        when the real class count may be higher. has_more only means a
        larger offset still has collected rows -- and count may be below the
        requested limit when the result-size budget trimmed the page, so read
        count, not limit, and page on has_more.
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
        has_more only means a larger offset still has collected rows -- and
        count may be below the requested limit when the result-size budget
        trimmed the page, so read count, not limit, and page on has_more.
        """
        return _dump(
            analysis.apk_methods(session_id, class_name, offset=offset, limit=limit)
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
        still has collected rows -- and count may be below the requested limit
        when the result-size budget trimmed the page (each string can be 2000
        chars), so read count, not limit, and page on has_more. There is no
        items or constants field.
        """
        return _dump(analysis.apk_strings(session_id, offset=offset, limit=limit))

    @tools.tool(name="apk.xrefs")
    def apk_xrefs(
        session_id: str,
        method_name: str,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
        direction: str = "callers",
    ) -> dict[str, Any]:
        """List callers of a method, or the methods it calls (by direction).

        Answers with callers (class and method), method_name, direction, count,
        and has_more so a page that filled the limit is not read as the whole
        list. has_more is also set when the result-size budget trimmed the list;
        there is no offset here, so a trimmed list simply omits the rest.
        direction selects which way the xref runs: "callers" (the default) lists
        the methods that call method_name, under the callers field; "callees"
        lists the methods that method_name itself calls, and then the list field
        is callees, not callers. Either way each row is a class and method pair,
        and direction is echoed back so a callees reply is never read as callers.
        Any other direction is rejected as invalid_params.
        """
        return _dump(
            analysis.apk_xrefs(session_id, method_name, limit=limit, direction=direction)
        )

    @tools.tool(name="apk.string_xrefs")
    def apk_string_xrefs(
        session_id: str,
        value: str,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
        contains: bool = False,
    ) -> dict[str, Any]:
        """List the methods that reference a DEX string constant.

        Answers where a string is actually used -- the follow-up apk.strings
        cannot make, for tracing a hardcoded URL, key, or command back to the
        code that reads it. Answers with xrefs (each row a class and method plus
        the string it matched), value, match, strings_matched, count, has_more,
        and scan_capped. There is no callers or results field. By default value
        is matched exactly (match "exact"); set contains true to match any string
        that holds value as a substring (match "contains"), in which case several
        distinct strings can match and the per-row string names which one each
        edge belongs to. strings_matched is how many distinct strings matched;
        count is how many reference rows are returned. has_more is set when the
        limit or the result-size budget cut the rows (there is no offset, so a
        trimmed list simply omits the rest); scan_capped is set when the string
        scan hit its cap before the whole DEX was walked, so an empty or short
        result is not read as "referenced nowhere else". An empty value is
        rejected as invalid_params.
        """
        return _dump(
            analysis.apk_string_xrefs(session_id, value, limit=limit, contains=contains)
        )

    @tools.tool(name="apk.disassemble")
    def apk_disassemble(
        session_id: str,
        class_name: str,
        method_name: str,
        descriptor: str = "",
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=5000)] = 200,
    ) -> dict[str, Any]:
        """Disassemble one method's DEX bytecode (no jadx/JRE or apktool needed).

        Reads the method's Dalvik instructions straight from androguard, so it
        works where apk.decompile (jadx) and apk.decode (apktool) cannot run --
        and answers what apk.xrefs only points at: what a method actually does.
        Answers with instructions (each row idx, addr, mnemonic, operands),
        class_name, method_name, descriptor, access, count, total, offset,
        has_more, scan_capped, and overloads. addr is the code-unit offset (so
        branch targets line up); mnemonic/operands are the Dalvik opcode and its
        arguments (e.g. const-string, invoke-virtual). total is the number of
        instructions collected, capped at 20000; scan_capped is true when the
        method was longer. has_more only means a larger offset still has rows --
        and count may be below the requested limit when the result-size budget
        trimmed the page (a const-string operand can be 2000 chars), so read
        count, not limit, and page on has_more. overloads lists every descriptor
        for this method name in the class; when a name has more than one and no
        descriptor is given, the first by sorted descriptor is shown -- pass
        descriptor to pick another. An unknown class/method is not_found; a blank
        class_name or method_name is invalid_params. There is no smali, code or
        source field.
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
