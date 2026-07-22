import os

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from app.config import settings


class Base(DeclarativeBase):
    pass


# ── Module-level engine (FastAPI process) ──────────────────────────────
# Created at import time for the FastAPI server. Celery ForkPoolWorker
# children inherit this engine but *must not use it* — see get_engine().
engine = create_async_engine(
    settings.DATABASE_URL,
    echo=False,
    future=True,
    pool_size=10,
    max_overflow=20,
    pool_pre_ping=True,
)

_engine_pid: int | None = None
_engine_gen: int = 0
"""Generation counter bumped by ``task_utils._run()`` before each invocation.

When a Celery worker task finishes and closes its event loop, the next
task on the same process gets a new loop.  ``get_engine()`` checks this
counter and creates a fresh engine (with a new pool on the new loop)
whenever it changes, avoiding "Future attached to a different loop"
errors.
"""


def _bump_engine_gen() -> None:
    """Called by ``task_utils._run()`` before each coroutine invocation.

    This invalidates the current engine's generation so the next call to
    ``get_engine()`` creates a fresh engine with a new pool on the
    running event loop.
    """
    global _engine_gen
    _engine_gen += 1


def _create_engine() -> None:
    """Replace the module-level ``engine`` with a fresh instance.

    Called from :func:`get_engine` when a fork is detected, so the new
    engine lazily creates its connection pool on the **current process's**
    event loop.
    """
    global engine, _engine_pid
    engine = create_async_engine(
        settings.DATABASE_URL,
        echo=False,
        future=True,
        pool_size=10,
        max_overflow=20,
        pool_pre_ping=True,
    )
    _engine_pid = os.getpid()


def get_engine():
    """Return an async engine valid for the current process + event loop.

    Celery's ForkPoolWorker forks the parent process, so each child
    inherits the module-level ``engine`` whose connection pool is tied
    to the **parent's** event loop.  Using that inherited engine raises::

        RuntimeError: Future attached to a different loop

    This function detects the PID change (fork) **and** generation bumps
    (new event loop in the same process, signalled by
    ``task_utils._run()``) and creates a fresh engine in both cases.

    The new engine's pool is lazily initialised on the first connection,
    which will correctly bind to whatever event loop is running on that
    thread (the one set up by ``_run()`` in ``task_utils.py``).
    """
    if _engine_pid != os.getpid() or _engine_gen != getattr(get_engine, "_last_gen", -1):
        if _engine_pid != os.getpid():
            _create_engine()
        else:
            # Same process, new event loop — replace engine to get a
            # fresh pool on the running loop.
            global engine
            engine = create_async_engine(
                settings.DATABASE_URL,
                echo=False,
                future=True,
                pool_size=10,
                max_overflow=20,
                pool_pre_ping=True,
            )
        get_engine._last_gen = _engine_gen
    return engine


class _LazySessionMaker:
    """Process-aware :class:`AsyncSession` factory.

    Works exactly like ``async with AsyncSessionLocal() as session:``,
    but resolves the engine dynamically via :func:`get_engine` so that
    forked Celery workers automatically get a fresh engine on their own
    event loop.

    Usage is identical to the old ``async_sessionmaker`` instance::

        async with AsyncSessionLocal() as session:
            ...

    No code changes are needed in any caller.
    """

    def __call__(self, **kwargs):
        kwargs.setdefault("expire_on_commit", False)
        return AsyncSession(bind=get_engine(), **kwargs)

    async def __aenter__(self):
        session = self()
        self._session = session
        return await session.__aenter__()

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        return await self._session.__aexit__(exc_type, exc_val, exc_tb)


AsyncSessionLocal: _LazySessionMaker = _LazySessionMaker()


async def get_db():
    async with AsyncSessionLocal() as session:
        yield session
