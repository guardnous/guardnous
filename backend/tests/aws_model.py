"""A stand-in AWS session that is checked against botocore's own API definitions.

No network and no credentials are used. For every call a collector makes, the
fake client:

* fails if the operation does not exist on that service,
* validates the arguments against the operation's input shape,
* fails if ``get_paginator`` is used on an operation that cannot be paginated,
* returns a response with **every** field of the output shape filled in.

Because every field is present, a collector that reads a misspelt or
non-existent response key ends up with an empty value, which the tests catch.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Callable

import boto3
from botocore.validate import ParamValidator

_TIME = datetime(2026, 1, 1, tzinfo=timezone.utc)


def sample(shape, depth: int = 0) -> Any:
    """A value of this shape with every member present."""
    kind = shape.type_name
    if kind == "structure":
        if depth > 6:
            return {}
        return {name: sample(member, depth + 1) for name, member in shape.members.items()}
    if kind == "list":
        return [] if depth > 6 else [sample(shape.member, depth + 1)]
    if kind == "map":
        return {} if depth > 6 else {"key": sample(shape.value, depth + 1)}
    if kind == "string":
        if getattr(shape, "enum", None):
            return shape.enum[0]
        return "sample".ljust(int(shape.metadata.get("min", 0)), "x")
    if kind == "boolean":
        return True
    if kind in ("integer", "long"):
        return 7
    if kind in ("float", "double"):
        return 1.5
    if kind == "timestamp":
        return _TIME
    if kind == "blob":
        return b"sample"
    raise AssertionError(f"unhandled shape type {kind}")


class AwsError(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.response = {"Error": {"Code": code}}


class ModelClient:
    def __init__(self, service: str, region: str, session: "ModelSession"):
        # No default region, as in production: a regional service asked for without
        # one raises NoRegionError here, exactly as it does against real AWS.
        self._real = boto3.Session(aws_access_key_id="x", aws_secret_access_key="x").client(
            service, region_name=region or None,
        )
        self._service, self._session = service, session

    def _operation(self, method: str) -> str:
        mapping = self._real.meta.method_to_api_mapping
        assert method in mapping, f"{self._service} has no operation '{method}'"
        return mapping[method]

    def __getattr__(self, method: str):
        operation = self._operation(method)
        model = self._real.meta.service_model.operation_model(operation)

        def call(**kwargs):
            self._session.calls.append((self._service, method, kwargs))
            if model.input_shape is not None:
                report = ParamValidator().validate(kwargs, model.input_shape)
                assert not report.has_errors(), f"{self._service}.{method}: {report.generate_report()}"
            else:
                assert not kwargs, f"{self._service}.{method} takes no arguments"
            override = self._session.overrides.get((self._service, method))
            if isinstance(override, Exception):
                raise override
            response = sample(model.output_shape) if model.output_shape is not None else {}
            if override is not None:
                override(response, kwargs)
            return response
        return call

    def get_paginator(self, method: str):
        self._operation(method)
        assert self._real.can_paginate(method), f"{self._service}.{method} cannot be paginated"
        client = self

        class Paginator:
            def paginate(self, **kwargs):
                return [getattr(client, method)(**kwargs)]
        return Paginator()


class ModelSession:
    """``overrides[(service, method)]`` is an exception to raise, or a function
    ``(response, kwargs)`` that edits the generated response in place."""

    def __init__(self, overrides: dict[tuple[str, str], Callable | Exception] | None = None):
        self.overrides = overrides or {}
        self.calls: list[tuple[str, str, dict]] = []
        self._clients: dict[tuple[str, str], ModelClient] = {}

    def client(self, service: str, region_name: str | None = None):
        key = (service, region_name or "")
        if key not in self._clients:
            self._clients[key] = ModelClient(service, region_name or "", self)
        return self._clients[key]
