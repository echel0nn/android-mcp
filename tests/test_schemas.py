"""Every registered MCP tool exposes a valid JSON Schema 2020-12 input schema.

The HTTP transport surfaces each tool's input schema at
``GET /tools/<name>/schema``. AILA's VR module wires android-mcp through
the same bridge layer that consumes audit-mcp's schemas — both bridges
require draft-2020-12 documents so kwarg validation lines up with what
Pydantic / FastMCP emits internally.

This file boots the FastAPI app once via ``http_api.build_app``,
enumerates the registered tools through ``GET /tools``, and then walks
``GET /tools/<name>/schema`` for each tool. Two failure modes the test
catches:

* The schema endpoint falls through to the ``{"description": "no schema
  available"}`` placeholder — meaning ``_tool_schema`` could not locate
  any of the three schema attributes on the FastMCP tool object. Either
  FastMCP changed the attribute name (we want to know immediately) or
  the tool author wrote a handler without typed kwargs (also a bug —
  the bridge cannot validate calls into it).
* The schema document is structurally invalid against draft 2020-12.
  ``Draft202012Validator.check_schema`` raises ``SchemaError`` on the
  first metadata violation; pytest surfaces the offending tool name and
  the validator's own diagnostic.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from android_mcp.http_api import build_app


@pytest.fixture(scope="module")
def client() -> TestClient:
    return TestClient(build_app())


def _list_tool_names(client: TestClient) -> list[str]:
    response = client.get("/tools")
    assert response.status_code == 200, f"GET /tools returned {response.status_code}: {response.text}"
    body = response.json()
    assert isinstance(body, dict) and "tools" in body, f"GET /tools body shape unexpected: {body!r}"
    names = [row["name"] for row in body["tools"]]
    # The server must register SOMETHING — an empty registry means
    # _register_all silently swallowed every import error.
    assert names, "GET /tools returned an empty tool list — server.py registered nothing"
    return names


def test_tools_endpoint_lists_at_least_the_four_scaffold_tools(client: TestClient) -> None:
    """The four scaffold tools registered since day one MUST appear.

    Pins the floor independently of later iterations (B-14 lifts this
    to 13+ once it lands). If a future commit accidentally drops one of
    these from ``_register_all``, this assertion catches it before the
    AILA bridge tries to call into a missing tool.
    """
    names = set(_list_tool_names(client))
    expected_floor = {"androguard_summary", "apktool_decode", "jadx_decompile", "mobsf_scan"}
    missing = expected_floor - names
    assert not missing, f"GET /tools missing scaffold tools: {sorted(missing)}"


def test_every_tool_exposes_valid_draft_2020_12_schema(client: TestClient) -> None:
    """``GET /tools/<name>/schema`` returns a structurally valid Draft 2020-12 doc.

    Walks every name from ``GET /tools`` so this stays correct as new
    tool modules land. Fails loudly if:

    * any tool returns the ``"no schema available"`` placeholder, OR
    * any tool returns a schema that fails ``Draft202012Validator.check_schema``.
    """
    jsonschema = pytest.importorskip("jsonschema", reason="jsonschema dev dep not installed")
    from jsonschema.exceptions import SchemaError

    names = _list_tool_names(client)
    placeholders: list[str] = []
    invalid: list[tuple[str, str]] = []

    for name in names:
        response = client.get(f"/tools/{name}/schema")
        assert response.status_code == 200, (
            f"GET /tools/{name}/schema returned {response.status_code}: {response.text}"
        )
        schema = response.json()
        if schema == {"description": "no schema available"}:
            placeholders.append(name)
            continue
        try:
            jsonschema.Draft202012Validator.check_schema(schema)
        except SchemaError as exc:
            invalid.append((name, str(exc)))

    failures: list[str] = []
    if placeholders:
        failures.append(
            f"tools returning the 'no schema available' placeholder: {sorted(placeholders)}",
        )
    if invalid:
        failures.append(
            "tools with schemas that fail Draft202012Validator.check_schema:\n  "
            + "\n  ".join(f"{n}: {err}" for n, err in invalid),
        )
    assert not failures, "\n".join(failures)


def test_unknown_tool_schema_returns_404(client: TestClient) -> None:
    """``GET /tools/<bogus>/schema`` returns 404 — confirms the lookup branch."""
    response = client.get("/tools/__definitely_not_a_real_tool__/schema")
    assert response.status_code == 404, (
        f"unknown tool schema lookup returned {response.status_code}, expected 404"
    )
