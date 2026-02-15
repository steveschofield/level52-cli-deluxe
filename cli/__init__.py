"""Guardian CLI package.

Keep this module import-light: importing `cli.main` here triggers a `runpy` warning
when running `python -m cli.main` because the module gets imported before it is
executed as `__main__`.
"""

__all__ = ["app", "main"]


def __getattr__(name: str):
    if name in __all__:
        from .main import app, main

        return {"app": app, "main": main}[name]
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    return sorted(set(globals().keys()) | set(__all__))
