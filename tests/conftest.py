import pytest

from chameleon.patch import integrate, redis_store


@pytest.fixture(autouse=True)
def _isolate_patch_side_effects():
    """Tests never touch the real Redis or rewrite the real app files; the
    tests for those two opt back in explicitly."""
    redis_store.use(None)
    integrate.ENABLED = False
    yield
    redis_store.use(None)
    integrate.ENABLED = False
