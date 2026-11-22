import pytest

from lab import cvss, jsonschema_lite


@pytest.mark.parametrize(
    "vector,score",
    [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
        ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 6.5),
        ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8),
        ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", 5.9),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3),
        ("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", 0.0),
        ("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.6),
    ],
)
def test_base_score(vector, score):
    assert cvss.base_score(vector) == score


def test_severity_bands():
    assert [cvss.severity(s) for s in (0, 3.9, 4.0, 6.9, 7.0, 8.9, 9.0)] == [
        "info",
        "low",
        "medium",
        "medium",
        "high",
        "high",
        "critical",
    ]


@pytest.mark.parametrize("vector", ["AV:N/AC:L", "CVSS:3.1/AV:N", "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CVSS:4.0/AV:N"])
def test_bad_vectors(vector):
    with pytest.raises(cvss.CVSSError):
        cvss.base_score(vector)


def test_jsonschema_lite():
    schema = {
        "type": "object",
        "required": ["id", "items"],
        "additionalProperties": False,
        "properties": {
            "id": {"type": "string", "pattern": "^[a-z]+$", "minLength": 2},
            "level": {"enum": ["low", "high"]},
            "n": {"type": "integer", "minimum": 1, "maximum": 3},
            "items": {"type": "array", "minItems": 1, "items": {"$ref": "#/$defs/item"}},
        },
        "$defs": {"item": {"type": "object", "required": ["k"], "properties": {"k": {"type": ["string", "null"]}}}},
    }
    assert jsonschema_lite.validate({"id": "ab", "items": [{"k": None}], "n": 2, "level": "low"}, schema) == []
    errors = jsonschema_lite.validate({"id": "A", "items": [], "n": True, "level": "mid", "x": 1}, schema)
    text = "\n".join(errors)
    for needle in ("does not match", "shorter", "at least 1", "expected integer", "not one of", "unexpected key 'x'"):
        assert needle in text
    assert "missing required key 'k'" in jsonschema_lite.validate({"id": "ab", "items": [{}]}, schema)[0]


def test_jsonschema_lite_max_length_and_max_items():
    from lab import jsonschema_lite

    schema = {"type": "object", "properties": {"s": {"type": "string", "maxLength": 3}, "a": {"type": "array", "maxItems": 2}}}
    assert jsonschema_lite.validate({"s": "abc", "a": [1, 2]}, schema) == []
    assert len(jsonschema_lite.validate({"s": "abcd", "a": [1, 2, 3]}, schema)) == 2
