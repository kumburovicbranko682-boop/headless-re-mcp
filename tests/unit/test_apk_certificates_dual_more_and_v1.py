"""``apk.certificates`` merges two independent lists and derives v1 from names.

The reply is assembled from *two separate* androguard reads, each capped on its
own, and a v1-signed flag derived from a *third* fact::

    try:
        names = apk.get_signature_names();          # META-INF/*.RSA (v1/JAR sig files)
    except Exception:
        names = [];                                  # older/odd androguard -> none
    sig_files, files_more = <cap names at _MAX_CERTIFICATES>;
    certs_more = False;
    for cert in apk.get_certificates():              # the parsed X.509 certs (any scheme)
        if len(items) >= _MAX_CERTIFICATES:
            certs_more = True; break;
        try:
            items.append({subject, issuer, serial, sha256});
        except Exception:
            continue;                                # a cert object we cannot read -> skip
    return {
        "signature_files": sig_files,
        "certificates": items,
        "v1_signed": bool(names),                    # v1 == there ARE JAR signature files
        "has_more": certs_more or files_more,        # either list overflowing flags partial
    };

The existing ``certificates`` test feeds 40 signature names *and* 40 certs -- both
over the 32 cap, both well-formed. That pins the field names and the happy path,
but it over-determines everything the branches decide: ``has_more`` is True on
both operands at once, ``v1_signed`` is True with certs also present, and no read
ever fails. Four things a symmetric, well-formed fixture cannot show:

* **Each side of ``has_more`` flags partial on its own.** ``signature_files`` and
  ``certificates`` overflow independently -- an APK can carry dozens of JAR entries
  but one cert, or one signer with a huge chain. With both capped, dropping either
  ``certs_more`` or ``files_more`` from the OR stays green. These pin the two
  mirror cases: files-over-cap with certs under it, and certs-over-cap with files
  under it, each of which must set ``has_more`` alone.

* **``v1_signed`` follows the signature *names*, not the certificates.** A v2/v3-only
  APK (signed with the APK Signature Scheme, no META-INF JAR signatures) parses
  certificates but has *no* signature files, so ``v1_signed`` must be False even
  though ``certificates`` is non-empty. Tie the flag to ``certificates`` instead
  and every modern v2-signed APK is mislabelled v1-signed.

* **A ``get_signature_names`` that raises means "no v1 files", not a crash.** Some
  androguard builds/inputs throw here; the ``except`` makes ``names`` empty
  (``v1_signed`` False, ``signature_files`` empty) while certificate parsing still
  runs. Let it escape and the whole tool fails on an APK it could otherwise read.

* **A certificate object we cannot read is skipped, not fatal.** Certificate shapes
  vary by androguard version; if one raises on attribute access the ``except``
  drops just that entry and the readable certs still come back, rather than losing
  the entire list to one bad element.

These drive ``ApkClient.certificates`` through fake APKs -- no androguard, no
signing -- and shrink nothing: the real 32 cap is used, with list sizes chosen so
only one side overflows at a time.
"""

from __future__ import annotations

from pathlib import Path

from headless_re_mcp.backends.apk.client import _MAX_CERTIFICATES, ApkClient


class _Cert:
    """A readable certificate with the four fields the parser copies."""

    def __init__(self, index: int) -> None:
        self.subject = f"CN=signer{index}"
        self.issuer = "CN=issuer"
        self.serial_number = index
        self.sha256_fingerprint = f"{index:064x}"


class _UnreadableCert:
    """A certificate whose ``subject`` raises -- a shape androguard cannot render."""

    issuer = "CN=issuer"
    serial_number = 7
    sha256_fingerprint = "bb"

    @property
    def subject(self) -> str:
        raise ValueError("this certificate object cannot expose a subject")


def _client(apk: object) -> ApkClient:
    client = ApkClient()
    client._apk = lambda _path: apk  # type: ignore[method-assign]
    return client


class _FilesOverflowApk:
    """Many JAR signature files, but only a couple of parsed certificates."""

    def get_signature_names(self) -> list[str]:
        return [f"META-INF/CERT{index}.RSA" for index in range(_MAX_CERTIFICATES + 8)]

    def get_certificates(self) -> list[_Cert]:
        return [_Cert(0), _Cert(1)]


class _CertsOverflowApk:
    """A single signature file, but a long certificate chain past the cap."""

    def get_signature_names(self) -> list[str]:
        return ["META-INF/CERT.RSA"]

    def get_certificates(self) -> list[_Cert]:
        return [_Cert(index) for index in range(_MAX_CERTIFICATES + 8)]


class _V2OnlyApk:
    """v2/v3-signed: certificates parse, but there are no META-INF JAR sig files."""

    def get_signature_names(self) -> list[str]:
        return []

    def get_certificates(self) -> list[_Cert]:
        return [_Cert(0)]


class _NamesRaiseApk:
    """An androguard build/input where ``get_signature_names`` throws."""

    def get_signature_names(self) -> list[str]:
        raise RuntimeError("signature block is unreadable")

    def get_certificates(self) -> list[_Cert]:
        return [_Cert(0)]


class _OneBadCertApk:
    """A chain with one certificate the parser cannot read between two good ones."""

    def get_signature_names(self) -> list[str]:
        return ["META-INF/CERT.RSA"]

    def get_certificates(self) -> list[object]:
        return [_Cert(0), _UnreadableCert(), _Cert(2)]


def test_the_signature_files_cap_alone_flags_has_more() -> None:
    """Overflowing JAR entries flag the reply partial even with few certificates.

    ``certs_more`` is False (two certs, under the cap), so only ``files_more`` can
    set ``has_more``. It must -- otherwise a caller reads a clipped signature-file
    list as every signer.
    """
    payload = _client(_FilesOverflowApk()).certificates(Path("app.apk"))

    assert payload["has_more"] is True
    assert len(payload["signature_files"]) == _MAX_CERTIFICATES
    assert len(payload["certificates"]) == 2
    assert payload["v1_signed"] is True


def test_the_certificate_cap_alone_flags_has_more() -> None:
    """A long cert chain flags the reply partial even with one signature file.

    The mirror of the above: ``files_more`` is False, so only ``certs_more`` can
    raise ``has_more``.
    """
    payload = _client(_CertsOverflowApk()).certificates(Path("app.apk"))

    assert payload["has_more"] is True
    assert len(payload["certificates"]) == _MAX_CERTIFICATES
    assert len(payload["signature_files"]) == 1
    assert payload["v1_signed"] is True


def test_a_v2_only_apk_has_certificates_but_is_not_v1_signed() -> None:
    """No META-INF JAR files means v1_signed False, even with certificates present.

    ``v1_signed`` is ``bool(names)``, tied to the signature *files*, not the parsed
    certificates -- a modern v2/v3-signed APK carries certs but no v1 JAR
    signatures, and must not be mislabelled v1-signed.
    """
    payload = _client(_V2OnlyApk()).certificates(Path("app.apk"))

    assert payload["v1_signed"] is False
    assert payload["signature_files"] == []
    assert len(payload["certificates"]) == 1
    assert payload["has_more"] is False


def test_a_raising_signature_names_means_no_v1_files_not_a_crash() -> None:
    """``get_signature_names`` throwing yields empty names, and certs still parse.

    The ``except`` turns an unreadable signature block into "no v1 files"
    (v1_signed False, signature_files empty) rather than failing the whole tool;
    certificate parsing is independent and still runs.
    """
    payload = _client(_NamesRaiseApk()).certificates(Path("app.apk"))

    assert payload["v1_signed"] is False
    assert payload["signature_files"] == []
    assert len(payload["certificates"]) == 1


def test_one_unreadable_certificate_is_skipped_not_fatal() -> None:
    """A cert object that raises on read is dropped; the readable ones survive.

    The per-cert ``except: continue`` keeps one odd certificate shape from taking
    down the entire list -- the two good certs still come back.
    """
    payload = _client(_OneBadCertApk()).certificates(Path("app.apk"))

    subjects = [cert["subject"] for cert in payload["certificates"]]
    assert subjects == ["CN=signer0", "CN=signer2"]
    assert payload["v1_signed"] is True
