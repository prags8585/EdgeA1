"""Demo target application: the four demo apps (chameleon.apps) served together.

This is only a demo target, not the product. Each app carries its own code
patches, rendered into its source by chameleon.patch.integrate when a patch is
approved; serve with --reload-dir chameleon/apps so a new patch goes live as
soon as its file is rewritten.
"""
from __future__ import annotations

from fastapi import FastAPI

from ..apps import chat_app, files_app, login_app, search_app
from ..apps.files_app import CANARY_API_KEY  # noqa: F401 - re-exported for callers and tests
from ..apps.login_app import CANARY_ADMIN_PASSWORD  # noqa: F401

APPS = {"login": login_app, "search": search_app, "files": files_app, "chat": chat_app}

app = FastAPI(title="NanoPot demo app")
for module in APPS.values():
    app.include_router(module.router)


@app.get("/patches")
def installed_patches():
    """Which code patches each app is running right now."""
    return {name: [{"rule_id": g.rule_id, "patch_id": g.patch_id, "attack_type": g.attack_type,
                    "fields": list(g.fields)} for g in module.patches.guards]
            for name, module in APPS.items()}
