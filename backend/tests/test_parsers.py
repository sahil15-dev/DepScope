import json

import pytest
from depscope.errors import ScanError
from depscope.models import Coordinate, Directness, Ecosystem, ManifestFormat, Resolution
from depscope.parsers import ParseLimits, parse_manifest

REQ = ManifestFormat.REQUIREMENTS
NPM = ManifestFormat.NPM_LOCK


def test_python_pin_normalization_continuations_hashes_and_duplicate_occurrences() -> None:
    contents = (
        "\ufeff# first line\r\n\r\n"
        " My_Pkg[HTTP2]==v1.2.0 \\\r\n"
        "  --hash=sha256:" + "a" * 64 + " # inline comment\r\n"
        "my.pkg==1.2\r\n"
        "other==01.0-rc1\r\n"
    ).encode()
    manifest = parse_manifest(contents, REQ)
    assert [item.line for item in manifest.occurrences] == [3, 5, 6]
    assert manifest.occurrences[0].extras == ("http2",)
    assert manifest.coordinates == (
        Coordinate(Ecosystem.PYPI, "my-pkg", "1.2"),
        Coordinate(Ecosystem.PYPI, "other", "1rc1"),
    )
    assert all(item.resolution is Resolution.DECLARED_PIN for item in manifest.occurrences)


@pytest.mark.parametrize(
    ("text", "state", "reason"),
    [
        ("alpha>=1.0,<3", Resolution.RANGE, "no_single_exact_pin"),
        ("alpha==1.*", Resolution.RANGE, "no_single_exact_pin"),
        ("alpha==1,>=1", Resolution.RANGE, "no_single_exact_pin"),
        ("alpha", Resolution.UNPINNED, "no_version_specifier"),
        ("alpha===opaque-123", Resolution.UNRESOLVED, "arbitrary_version_equality"),
        (
            "alpha==1; python_version == '3.12'",
            Resolution.UNRESOLVED,
            "target_environment_required",
        ),
        (
            "alpha @ https://user:example@invalid.invalid/a#fragment",
            Resolution.UNRESOLVED,
            "external_reference",
        ),
        ("git+https://invalid.invalid/a#egg=alpha", Resolution.UNRESOLVED, "external_reference"),
        ("./private/a.whl", Resolution.UNRESOLVED, "local_reference"),
        ("local-archive.whl", Resolution.UNRESOLVED, "local_reference"),
        ("C:\\example\\not-read.whl", Resolution.UNRESOLVED, "local_reference"),
        ("-e ./private", Resolution.UNRESOLVED, "editable_install"),
        ("-rother.txt", Resolution.UNRESOLVED, "file_directive"),
        ("--constraint=other.txt", Resolution.UNRESOLVED, "file_directive"),
        ("--require-hashes", Resolution.UNRESOLVED, "unsupported_directive"),
        ("not valid < text", Resolution.INVALID, "invalid_requirement"),
        ("alpha==1 \\", Resolution.INVALID, "invalid_logical_line"),
        ("a" * 215 + "==1", Resolution.INVALID, "invalid_package_name"),
        ("alpha==" + "1" * 129, Resolution.UNRESOLVED, "unsupported_version"),
    ],
)
def test_python_never_queries_or_serializes_raw_unresolved_values(
    text: str,
    state: Resolution,
    reason: str,
) -> None:
    (item,) = parse_manifest(text.encode(), REQ).occurrences
    assert (item.resolution, item.reason, item.coordinate) == (state, reason, None)
    assert "https://" not in repr(item)
    assert "private" not in repr(item)


def test_conflicting_pins_and_index_override() -> None:
    conflict = parse_manifest(b"A_B==1.0\nA.B==2.0\nC==1", REQ)
    assert [item.reason for item in conflict.occurrences] == [
        "conflicting_pins",
        "conflicting_pins",
        None,
    ]
    assert [item.name for item in conflict.coordinates] == ["c"]
    indexed = parse_manifest(
        b"alpha==1\n--extra-index-url https://u:pw@invalid.invalid/simple", REQ
    )
    assert not indexed.coordinates
    assert {item.reason for item in indexed.occurrences} == {"package_index_override"}
    assert "invalid.invalid" not in repr(indexed)


def test_long_whitespace_and_malformed_hash_options_fail_safely() -> None:
    manifest = parse_manifest(b"alpha" + b" " * 500_000 + b"==3", REQ)
    assert manifest.occurrences[0].reason == "invalid_logical_line"
    manifest = parse_manifest(b"alpha==3 --hash=sha256:0000", REQ)
    assert not manifest.coordinates
    assert manifest.occurrences[0].reason == "invalid_hash_option"


def test_npm_root_alias_target_and_explicit_external_source() -> None:
    lock = {
        "lockfileVersion": 3,
        "packages": {
            "": {
                "dependencies": {
                    "alias": "npm:@scope/real",
                    "contradictory": "npm:real@^1",
                    "file": "file:../private.tar.gz",
                    "incomplete": "npm:",
                }
            },
            "node_modules/alias": {"version": "1.2.3"},
            "node_modules/contradictory": {"name": "mismatch", "version": "1.2.3"},
            "node_modules/file": {"version": "1.2.3"},
            "node_modules/incomplete": {"version": "1.2.3"},
        },
    }
    result = parse_manifest(json.dumps(lock).encode(), NPM)
    assert result.coordinates == (Coordinate(Ecosystem.NPM, "@scope/real", "1.2.3"),)
    assert [item.reason for item in result.occurrences[1:]] == [
        "ambiguous_alias",
        "unverified_registry_source",
        "ambiguous_alias",
    ]
    assert "private.tar.gz" not in repr(result)


@pytest.mark.parametrize("version", [2, 3])
def test_modern_lock_uses_packages_not_legacy_tree(version: int) -> None:
    lock = {
        "lockfileVersion": version,
        "dependencies": {"bogus": {"version": "1.0.0"}},
        "packages": {
            "": {"dependencies": {"@scope/real": "^1", "alias": "npm:@scope/real@^1"}},
            "node_modules/@scope/real": {"version": "1.2.0"},
            "node_modules/alias": {"name": "@scope/real", "version": "1.2.0"},
            "node_modules/alias/node_modules/@scope/real": {"version": "2.0.0"},
            "node_modules/transitive": {"version": "3.0.0-beta.1+build"},
            "node_modules/local": {"link": True, "resolved": "packages/secret"},
            "packages/secret": {"name": "local", "version": "9.0.0"},
            "../private-url": {"version": "4.0.0"},
        },
    }
    manifest = parse_manifest(json.dumps(lock).encode(), NPM)
    assert manifest.lockfile_version == version
    assert [item.directness for item in manifest.occurrences[:4]] == [
        Directness.DIRECT,
        Directness.DIRECT,
        Directness.TRANSITIVE,
        Directness.TRANSITIVE,
    ]
    assert [(item.name, item.version) for item in manifest.coordinates] == [
        ("@scope/real", "1.2.0"),
        ("@scope/real", "2.0.0"),
        ("transitive", "3.0.0-beta.1+build"),
    ]
    assert manifest.occurrences[2].dependency_path == "node_modules/alias/node_modules/@scope/real"
    assert [item.reason for item in manifest.occurrences[4:]] == [
        "linked_or_bundled_source",
        "unsupported_install_path",
        "unsupported_install_path",
    ]
    assert "secret" not in repr(manifest) and "private-url" not in repr(manifest)


def test_legacy_lock_tree_and_alias_name() -> None:
    lock = {
        "lockfileVersion": 1,
        "dependencies": {
            "alias": {
                "version": "npm:@scope/real@1.2.0",
                "requires": {"not-installed": "^2"},
                "dependencies": {"child": {"version": "2.3.4"}},
            },
            "bad-child-tree": {"version": "2.1.0", "dependencies": []},
            "bad-alias": {"version": "npm:non-exact"},
        },
    }
    manifest = parse_manifest(json.dumps(lock).encode(), NPM)
    assert manifest.occurrences[0].directness is Directness.UNKNOWN
    assert manifest.occurrences[1].directness is Directness.TRANSITIVE
    assert manifest.occurrences[1].dependency_path == "node_modules/alias/node_modules/child"
    assert manifest.occurrences[-2].reason == "invalid_lock_entry"
    assert manifest.occurrences[-1].reason == "ambiguous_alias"
    assert [item.name for item in manifest.coordinates] == [
        "@scope/real",
        "bad-child-tree",
        "child",
    ]


@pytest.mark.parametrize(
    ("record", "reason"),
    [
        (None, "invalid_lock_entry"),
        ({"name": 1, "version": "1.2.3"}, "invalid_package_name"),
        ({"name": "UPPER", "version": "1.2.3"}, "missing_package_identity"),
        ({"version": "^1.2"}, "no_exact_registry_version"),
        ({"version": "1.2.3", "resolved": "file:../private.tgz"}, "unverified_registry_source"),
        (
            {"version": "1.2.3", "resolved": "https://registry.npmjs.org/a/-/a-9.9.9.tgz"},
            "unverified_registry_source",
        ),
        ({"version": "1.2.3", "resolved": "https://[bad"}, "unverified_registry_source"),
        ({"version": "1.2.3", "resolved": 42}, "unverified_registry_source"),
        ({"version": "1.2.3", "inBundle": True}, "linked_or_bundled_source"),
    ],
)
def test_npm_rejects_unsupported_install_identities(record: object, reason: str) -> None:
    lock = {"lockfileVersion": 3, "packages": {"node_modules/a": record}}
    (item,) = parse_manifest(json.dumps(lock).encode(), NPM).occurrences
    assert item.coordinate is None
    assert item.reason == reason
    assert item.directness is Directness.UNKNOWN


@pytest.mark.parametrize(
    ("content", "format", "limits", "code"),
    [
        (b"1234", REQ, ParseLimits(max_file_bytes=3), "input_too_large"),
        (b"\xff", REQ, ParseLimits(), "invalid_encoding"),
        (b"alpha\x00beta", REQ, ParseLimits(), "invalid_encoding"),
        (b"a==1\nb==1", REQ, ParseLimits(max_occurrences=1), "too_many_entries"),
        (b"a==1\nb==1", REQ, ParseLimits(max_coordinates=1), "too_many_coordinates"),
        (b"{", NPM, ParseLimits(), "invalid_lockfile"),
        (b'{"lockfileVersion": 1, "lockfileVersion": 2}', NPM, ParseLimits(), "invalid_lockfile"),
        (b'{"lockfileVersion": NaN}', NPM, ParseLimits(), "invalid_lockfile"),
        (b'{"lockfileVersion": true}', NPM, ParseLimits(), "unsupported_lockfile_version"),
        (b'{"lockfileVersion": 3}', NPM, ParseLimits(), "invalid_lockfile"),
        (
            b'{"lockfileVersion": 3,"packages":{"node_modules/a":{},"node_modules/b":{}}}',
            NPM,
            ParseLimits(max_occurrences=1),
            "too_many_entries",
        ),
        (
            b'{"lockfileVersion": 2,"packages":{"node_modules/a/node_modules/b":{}}}',
            NPM,
            ParseLimits(max_lock_depth=1),
            "lockfile_too_deep",
        ),
        (
            b'{"lockfileVersion": 1,"dependencies":{"a":{"dependencies":{"b":{}}}}}',
            NPM,
            ParseLimits(max_lock_depth=1),
            "lockfile_too_deep",
        ),
    ],
)
def test_input_error_codes(
    content: bytes, format: ManifestFormat, limits: ParseLimits, code: str
) -> None:
    with pytest.raises(ScanError) as excinfo:
        parse_manifest(content, format, limits=limits)
    assert excinfo.value.code == code


def test_empty_inventory_and_exact_size_boundary() -> None:
    assert parse_manifest(b"# a", REQ, limits=ParseLimits(max_file_bytes=3)).occurrences == ()
    assert parse_manifest(b'{"lockfileVersion":3,"packages":{}}', NPM).coordinates == ()
    with pytest.raises(ValueError):
        ParseLimits(max_lock_depth=81)
