"""rung: a verification-evidence framework (shared vocabulary, evidence-bundle
schema, declarative policy, and a deterministic stdlib-only gate).

The runtime is stdlib-only and dependency-free; the build backend named in
pyproject.toml is a build-time tool, not a runtime dependency. `__version__` is
the single source of truth for the package version (read dynamically by the
build backend); it is distinct from what `rung version` prints (schema major +
gate sha256 + resolved paths)."""

__version__ = "0.1.0"

__all__ = ["__version__"]
