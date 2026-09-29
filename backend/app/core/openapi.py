from typing import Any

from fastapi import FastAPI
from fastapi.dependencies.models import Dependant
from fastapi.routing import APIRoute

from app.api.routes import router
from app.core.security import local_features, operator


def private_operation(dependency: Dependant) -> bool:
    return dependency.call in {local_features, operator} or any(
        private_operation(child) for child in dependency.dependencies
    )


def schema_references(value: Any) -> set[str]:
    if isinstance(value, dict):
        references = set()
        if isinstance(value.get("$ref"), str) and value["$ref"].startswith("#/components/schemas/"):
            references.add(value["$ref"].rsplit("/", 1)[-1])
        for child in value.values():
            references.update(schema_references(child))
        return references
    if isinstance(value, list):
        return set().union(*(schema_references(child) for child in value))
    return set()


def secure_schema(schema: dict[str, Any], *, public_demo: bool) -> dict[str, Any]:
    restricted = {
        (route.path, method.lower())
        for route in router.routes
        if isinstance(route, APIRoute)
        and route.methods is not None
        and private_operation(route.dependant)
        for method in route.methods
    }
    if not public_demo:
        schema.setdefault("components", {})["securitySchemes"] = {
            "OwnerBearer": {
                "type": "http",
                "scheme": "bearer",
                "description": (
                    "Configured owner token. If no owner token is configured, only explicit "
                    "loopback callers can act as the owner; remote access is still denied."
                ),
            },
            "IntegrationBearer": {
                "type": "http",
                "scheme": "bearer",
                "description": (
                    "Enabled, unexpired server-side credential reference with the operation's "
                    "listed scope. Windows ingestion also requires a matching connector binding."
                ),
            },
        }
    for path, operations in list(schema["paths"].items()):
        for method, operation in list(operations.items()):
            if public_demo and (
                (path, method) in restricted
                or {"Integrations", "Notifications"} & set(operation.get("tags", []))
            ):
                del operations[method]
                continue
            operation["parameters"] = [
                parameter
                for parameter in operation.get("parameters", [])
                if parameter.get("name", "").lower() != "authorization"
            ]
            if public_demo or path == "/health":
                operation["security"] = []
                continue
            operation["security"] = [{"OwnerBearer": []}]
            scope = None
            if path == "/ingest/windows":
                scope = "windows:ingest"
                operation["security"] = []
            elif method == "get" and path in {"/alerts", "/alerts/{alert_id}"}:
                scope = "alerts:read"
            elif path == "/alerts/{alert_id}/notify":
                scope = "alerts:notify"
            elif path == "/notifications/test":
                scope = "notifications:test"
            if scope:
                operation["security"].append({"IntegrationBearer": []})
                operation["x-required-integration-scope"] = scope
        if not operations:
            del schema["paths"][path]
    if public_demo:
        schemas = schema.get("components", {}).get("schemas", {})
        needed = schema_references(schema["paths"])
        pending = list(needed)
        while pending:
            name = pending.pop()
            for child in schema_references(schemas.get(name)) - needed:
                needed.add(child)
                pending.append(child)
        if schemas:
            schema["components"]["schemas"] = {
                name: definition for name, definition in schemas.items() if name in needed
            }
    return schema


class SentinelAPI(FastAPI):
    public_demo: bool = False

    def openapi(self) -> dict[str, Any]:
        return secure_schema(super().openapi(), public_demo=self.public_demo)
