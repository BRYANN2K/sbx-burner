import pytest

from lab import miniyaml

DOC = """\
# comment
schema_version: "1"
name: demo   # trailing comment
count: 3
ratio: 0.5
flag: true
nothing: null
empty:
url: https://example.com/a#frag
quoted: 'it''s: fine'
list: [a, "b, c", 3]
flow: {a: 1, b: two}
variants:
  linux:
    status: ready
    kit:
      - kits/a
      - kits/b
  macos: {status: planned}
items:
  - name: one
    hosts: [h1, h2]
  - name: two
    nested:
      deep: yes
  - plain
same_indent_list:
- x
- y
text: |
  line one
    indented # not a comment
  line three
folded: >-
  a
  b
after: done
"""


def test_document():
    d = miniyaml.loads(DOC)
    assert d["schema_version"] == "1"
    assert d["name"] == "demo"
    assert d["count"] == 3 and d["ratio"] == 0.5 and d["flag"] is True
    assert d["nothing"] is None and d["empty"] is None
    assert d["url"] == "https://example.com/a#frag"
    assert d["quoted"] == "it's: fine"
    assert d["list"] == ["a", "b, c", 3]
    assert d["flow"] == {"a": 1, "b": "two"}
    assert d["variants"]["linux"]["kit"] == ["kits/a", "kits/b"]
    assert d["variants"]["macos"] == {"status": "planned"}
    assert d["items"][0] == {"name": "one", "hosts": ["h1", "h2"]}
    assert d["items"][1] == {"name": "two", "nested": {"deep": "yes"}}
    assert d["items"][2] == "plain"
    assert d["same_indent_list"] == ["x", "y"]
    assert d["text"] == "line one\n  indented # not a comment\nline three\n"
    assert d["folded"] == "a b"
    assert d["after"] == "done"


def test_top_level_sequence_and_empty():
    assert miniyaml.loads("- a\n- b: 1\n  c: 2\n") == ["a", {"b": 1, "c": 2}]
    assert miniyaml.loads("") is None
    assert miniyaml.loads("recipes: []\n") == {"recipes": []}


def test_dates_stay_strings_when_quoted():
    assert miniyaml.loads('d: "2026-11-01"') == {"d": "2026-11-01"}
    assert miniyaml.loads("d: 2026-11-01") == {"d": "2026-11-01"}


@pytest.mark.parametrize(
    "text",
    [
        "a: &anchor 1",
        "a: *alias",
        "a: 1\na: 2",
        "a:\n\tb: 1",
        "a: [1, 2",
        "a: 1\n---\nb: 2",
        "a: 1\n    b: 2\n  c: 3",
        'a: "unterminated',
    ],
)
def test_rejects_outside_subset(text):
    with pytest.raises(miniyaml.YAMLError):
        miniyaml.loads(text)


def test_frontmatter():
    meta, body = miniyaml.split_frontmatter("---\nname: x\nagents: [claude]\n---\n\n# Title\n")
    assert meta == {"name": "x", "agents": ["claude"]}
    assert body == "# Title"
    assert miniyaml.split_frontmatter("# no frontmatter") == ({}, "# no frontmatter")
    with pytest.raises(miniyaml.YAMLError):
        miniyaml.split_frontmatter("---\nname: x\n")
