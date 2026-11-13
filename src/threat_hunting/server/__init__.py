"""Threat Hunting Server package."""

from .models import GraphResponse, HuntRequest, HuntResponse, ScenarioInfo


def __getattr__(name: str):
    """Keep replay/experimental imports independent of the legacy application."""
    if name == "app":
        from importlib import import_module

        application = import_module(".app", __name__).app
        globals()[name] = application
        return application
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = ["app", "HuntRequest", "HuntResponse", "GraphResponse", "ScenarioInfo"]
