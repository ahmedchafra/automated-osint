"""Vector strategy registry.

Each reconnaissance vector lives in its own module here and exposes a
`run(context)` coroutine. The orchestrator in `scan_service.py` becomes a
thin dispatcher: it looks up the strategy by vector name and calls it.

Adding a new vector is a single file: drop `vectors/my_new_vector.py`
with a `run(context)` function, register it in `STRATEGIES` below.
"""
from __future__ import annotations

from typing import Awaitable, Callable

from app.services.vectors.context import VectorContext

VectorRunner = Callable[[VectorContext], Awaitable[None]]

# Populated by each module's import below. The orchestrator iterates
# only over the names requested by the user, but having every strategy
# registered in one place makes the surface explicit.
from app.services.vectors import (  # noqa: E402  (import order matters for registry)
    identity as identity_strategy,
    infrastructure as infrastructure_strategy,
    search as search_strategy,
    services as services_strategy,
    username as username_strategy,
)

STRATEGIES: dict[str, VectorRunner] = {
    "INFRASTRUCTURE": infrastructure_strategy.run,
    "SERVICES": services_strategy.run,
    "IDENTITY": identity_strategy.run,
    "SEARCH": search_strategy.run,
    "USERNAME": username_strategy.run,
}


__all__ = ["STRATEGIES", "VectorContext", "VectorRunner"]
