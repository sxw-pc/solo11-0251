"""Reviewable image release chain: build manifest, signing, download, boot proof,
customer acceptance, withdrawal/fallback and tenant isolated cache.

The provisional modules ``image_build`` / ``image_delivery`` identify an image by
the *source* digest and accept a customer copied string.  This module never trusts
that identity: a releasable artifact pins source, dependencies, compiler, build
parameters, real image bytes and the signing subject separately, and every later
step is checked against the actual bytes / device measurement.

All state lives in sqlite tables prefixed ``ir_`` so the module can share a
connection with the rest of ``cloudcourt``.  Time is an explicit integer supplied
by the caller, which keeps expiry and business-window tests deterministic.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3

from . import image_build, image_delivery

# ---------------------------------------------------------------------------
# schema / small helpers
# ---------------------------------------------------------------------------

SCHEMA = """
CREATE TABLE IF NOT EXISTS ir_signers(
    subject TEXT PRIMARY KEY, secret TEXT NOT NULL, role TEXT
);
CREATE TABLE IF NOT EXISTS ir_devices(
    id TEXT PRIMARY KEY, customer TEXT NOT NULL, secret TEXT NOT NULL,
    online INTEGER NOT NULL DEFAULT 1, last_seen INTEGER
);
CREATE TABLE IF NOT EXISTS ir_manifests(
    build_id TEXT PRIMARY KEY,
    source_digest TEXT NOT NULL,
    deps_lock_digest TEXT NOT NULL,
    deps_json TEXT NOT NULL,
    compiler_id TEXT NOT NULL,
    compiler_digest TEXT NOT NULL,
    params_digest TEXT NOT NULL,
    params_json TEXT NOT NULL,
    image_digest TEXT NOT NULL,
    manifest_digest TEXT NOT NULL UNIQUE,
    signer TEXT NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS ir_releases(
    id TEXT PRIMARY KEY,
    build_id TEXT NOT NULL,
    manifest_digest TEXT NOT NULL,
    image_digest TEXT NOT NULL,
    mode TEXT NOT NULL,                 -- common | dedicated
    customer TEXT,
    tenant TEXT,
    scope_json TEXT NOT NULL,
    signer TEXT NOT NULL,
    signature TEXT NOT NULL,
    issued_at INTEGER NOT NULL,
    not_before INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    state TEXT NOT NULL DEFAULT 'published',  -- published | withdrawn
    fallback_release_id TEXT,
    withdrawn_at INTEGER,
    withdraw_reason TEXT
);
CREATE TABLE IF NOT EXISTS ir_configs(
    id TEXT PRIMARY KEY,
    customer TEXT NOT NULL,
    tenant TEXT,
    generation INTEGER NOT NULL,
    config_digest TEXT NOT NULL,
    config_json TEXT NOT NULL,
    signer TEXT NOT NULL,
    signature TEXT NOT NULL,
    issued_at INTEGER NOT NULL,
    not_before INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    grace_until INTEGER,
    state TEXT NOT NULL DEFAULT 'active',     -- active | rotated | revoked
    replaces TEXT
);
CREATE TABLE IF NOT EXISTS ir_orders(
    id TEXT PRIMARY KEY,
    customer TEXT NOT NULL,
    device_id TEXT NOT NULL,
    release_id TEXT NOT NULL,
    build_id TEXT NOT NULL,
    mode TEXT NOT NULL,
    expected_image_digest TEXT NOT NULL,
    expected_config_digest TEXT,
    original_delivery_id TEXT,
    replacement_for TEXT,
    state TEXT NOT NULL DEFAULT 'opened',
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS ir_downloads(
    id TEXT PRIMARY KEY,
    order_id TEXT NOT NULL,
    at INTEGER NOT NULL,
    actual_digest TEXT,
    state TEXT NOT NULL,                -- verified | rejected
    reason TEXT
);
CREATE TABLE IF NOT EXISTS ir_install_attempts(
    id TEXT PRIMARY KEY,
    order_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    at INTEGER NOT NULL,
    coordinate TEXT,
    resolved_digest TEXT,
    bundle_id TEXT,
    state TEXT NOT NULL,                -- verified | blocked
    reason TEXT
);
CREATE TABLE IF NOT EXISTS ir_measurements(
    id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL,
    order_id TEXT,
    at INTEGER NOT NULL,
    image_digest TEXT NOT NULL,
    config_digest TEXT,
    boot_id TEXT,
    signature TEXT,
    verified INTEGER NOT NULL,
    state TEXT NOT NULL                 -- recorded | invalid_attestation
);
CREATE TABLE IF NOT EXISTS ir_acceptances(
    id TEXT PRIMARY KEY,
    order_id TEXT NOT NULL,
    measurement_id TEXT,
    customer TEXT NOT NULL,
    at INTEGER NOT NULL,
    approved_config_digest TEXT,
    state TEXT NOT NULL,                -- accepted | rejected
    reason TEXT
);
CREATE TABLE IF NOT EXISTS ir_corrections(
    id TEXT PRIMARY KEY,
    order_id TEXT NOT NULL,
    at INTEGER NOT NULL,
    kind TEXT NOT NULL,
    observed_image_digest TEXT,
    measurement_id TEXT,
    replacement_order_id TEXT,
    note TEXT
);
CREATE TABLE IF NOT EXISTS ir_config_rotations(
    old_config_id TEXT PRIMARY KEY,
    new_config_id TEXT,
    customer TEXT,
    at INTEGER,
    grace_until INTEGER,
    signer TEXT,
    signature TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ir_withdrawals(
    release_id TEXT PRIMARY KEY,
    at INTEGER NOT NULL,
    reason TEXT,
    fallback_release_id TEXT,
    bundle_id TEXT
);
CREATE TABLE IF NOT EXISTS ir_windows(
    release_id TEXT NOT NULL,
    customer TEXT NOT NULL,
    run_until INTEGER NOT NULL,
    note TEXT,
    PRIMARY KEY(release_id, customer)
);
CREATE TABLE IF NOT EXISTS ir_bundles(
    id TEXT PRIMARY KEY,
    signer TEXT NOT NULL,
    signature TEXT NOT NULL,
    issued_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    payload_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ir_device_evidence(
    device_id TEXT NOT NULL,
    bundle_id TEXT NOT NULL,
    staged_at INTEGER NOT NULL,
    PRIMARY KEY(device_id, bundle_id)
);
CREATE TABLE IF NOT EXISTS ir_recovery_cases(
    release_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    customer TEXT NOT NULL,
    measured_digest TEXT NOT NULL,
    fallback_release_id TEXT,
    offline INTEGER NOT NULL DEFAULT 0,
    evidence_id TEXT,
    window_until INTEGER,
    PRIMARY KEY(release_id, device_id)
);
CREATE TABLE IF NOT EXISTS ir_cache_entries(
    scope TEXT NOT NULL,               -- shared | customer:<id>
    digest TEXT NOT NULL,
    kind TEXT NOT NULL DEFAULT 'image',
    customer TEXT,
    blob BLOB,
    size INTEGER,
    created_at INTEGER,
    quarantined INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY(scope, digest)
);
CREATE TABLE IF NOT EXISTS ir_cache_aliases(
    scope TEXT NOT NULL,
    coordinate TEXT NOT NULL,
    digest TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'clean',  -- clean | poisoned
    PRIMARY KEY(scope, coordinate)
);
CREATE TABLE IF NOT EXISTS ir_reproductions(
    id TEXT PRIMARY KEY,
    build_id TEXT NOT NULL,
    machine_id TEXT NOT NULL,
    at INTEGER NOT NULL,
    method TEXT NOT NULL,              -- bytes | log_only
    pinned_digest TEXT NOT NULL,
    observed_digest TEXT,
    status TEXT NOT NULL               -- byte_identical | byte_differs | log_claim_insufficient
);
CREATE TABLE IF NOT EXISTS ir_customer_current(
    customer TEXT PRIMARY KEY,
    current_release_id TEXT,
    current_image_digest TEXT,
    current_config_digest TEXT,
    accepted_order_id TEXT,
    updated_at INTEGER
);
CREATE TABLE IF NOT EXISTS ir_global_pointer(
    channel TEXT PRIMARY KEY,
    release_id TEXT NOT NULL,
    image_digest TEXT NOT NULL,
    updated_at INTEGER
);
"""

# Cache kinds that may never live in the shared image cache.
CUSTOMER_MATERIAL_KINDS = frozenset(
    {"customer_key", "customer_config", "config_envelope", "tenant_policy", "secret"}
)


def init_schema(db):
    db.executescript(SCHEMA)
    if db.row_factory is not sqlite3.Row:
        db.row_factory = sqlite3.Row
    return db


def _ensure(db):
    # executescript is idempotent and matches the codebase convention of each
    # entry point installing its own schema.
    return init_schema(db)


def _commit(db):
    try:
        db.commit()
    except sqlite3.Error:
        pass


def _row(db, sql, args=()):
    cur = db.execute(sql, args)
    r = cur.fetchone()
    return dict(r) if r is not None else None


def _rows(db, sql, args=()):
    return [dict(r) for r in db.execute(sql, args).fetchall()]


def canonical(obj) -> bytes:
    """Deterministic canonical bytes used for digests and signatures."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_hex(data) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def digest_json(obj) -> str:
    return sha256_hex(canonical(obj))


def _mac(secret: str, payload: dict) -> str:
    key = secret if isinstance(secret, bytes) else str(secret).encode("utf-8")
    return hmac.new(key, canonical(payload), hashlib.sha256).hexdigest()


def _same_sig(a: str, b: str) -> bool:
    return bool(a) and bool(b) and hmac.compare_digest(str(a), str(b))


# ---------------------------------------------------------------------------
# trust roots: signing subjects and device attestation keys
# ---------------------------------------------------------------------------

def register_signer(db, subject, secret, role="issuer"):
    _ensure(db)
    db.execute(
        "INSERT INTO ir_signers(subject,secret,role) VALUES(?,?,?) "
        "ON CONFLICT(subject) DO UPDATE SET secret=excluded.secret, role=excluded.role",
        (subject, secret, role),
    )
    _commit(db)
    return {"decision": "signer_registered", "subject": subject}


def register_device(db, device_id, customer, secret, online=True, last_seen=None):
    _ensure(db)
    db.execute(
        "INSERT INTO ir_devices(id,customer,secret,online,last_seen) VALUES(?,?,?,?,?) "
        "ON CONFLICT(id) DO UPDATE SET customer=excluded.customer, secret=excluded.secret, "
        "online=excluded.online, last_seen=excluded.last_seen",
        (device_id, customer, secret, 1 if online else 0, last_seen),
    )
    _commit(db)
    return {"decision": "device_registered", "device_id": device_id}


def set_device_online(db, device_id, online=True, at=None):
    _ensure(db)
    db.execute(
        "UPDATE ir_devices SET online=?, last_seen=? WHERE id=?",
        (1 if online else 0, at if at is not None else None, device_id),
    )
    _commit(db)
    return {"decision": "device_presence_updated", "device_id": device_id, "online": bool(online)}


# ---------------------------------------------------------------------------
# build manifests: six independent pins, real image identity
# ---------------------------------------------------------------------------

def record_legacy_build(db, build_id, source_bytes, compiler, recipe):
    """Write through the provisional build ledger and return its source digest.

    The legacy row keeps advertising the source digest as ``advertised_digest``;
    callers must additionally call :func:`pin_manifest` to obtain a real
    artifact identity.
    """
    _ensure(db)
    return image_build.record(db, build_id, source_bytes, compiler, recipe)


def provisional_accept(db, delivery_id, build_id, customer, offered_digest):
    """Write through the provisional string-comparison delivery ledger."""
    _ensure(db)
    return image_delivery.provisional(db, delivery_id, build_id, customer, offered_digest)


def _normalise_deps(dependencies):
    out = []
    for dep in dependencies or []:
        if isinstance(dep, (tuple, list)):
            name, version, blob = dep
            digest = sha256_hex(blob)
        else:
            name = dep["name"]
            version = dep.get("version", "")
            if dep.get("bytes") is not None:
                digest = sha256_hex(dep["bytes"])
            elif dep.get("digest"):
                digest = dep["digest"]
            else:
                raise ValueError("dependency requires bytes or digest")
        out.append({"name": name, "version": str(version), "digest": digest})
    return sorted(out, key=lambda d: (d["name"], d["version"], d["digest"]))


def pin_manifest(db, build_id, *, signer, at=0,
                 source_bytes=None, source_digest=None,
                 dependencies=None,
                 compiler_id=None, compiler_digest=None, compiler_bytes=None,
                 params=None, build_params=None,
                 image_bytes=None, image_digest=None):
    """Pin every input and the real image bytes of a build.

    Returns the separate digests plus a ``manifest_digest`` committing to all of
    them.  Two builds sharing source bytes still get different
    ``image_digest`` / ``manifest_digest`` when compiler, dependencies, params
    or the produced bytes differ.
    """
    _ensure(db)
    params = params if params is not None else build_params
    params = dict(params or {})

    if source_bytes is not None:
        source_digest = sha256_hex(source_bytes)
    if not source_digest:
        return {"decision": "source_identity_required"}

    deps = _normalise_deps(dependencies)
    deps_lock_digest = digest_json(deps)

    if compiler_bytes is not None:
        compiler_digest = sha256_hex(compiler_bytes)
    compiler_id = compiler_id or "unspecified-compiler"
    if not compiler_digest:
        # Pin the compiler *identity* separately from its id string; callers
        # that have the real toolchain bytes should pass compiler_bytes.
        compiler_digest = digest_json({"compiler_id": compiler_id})

    params_digest = digest_json(params)

    if image_bytes is not None:
        image_digest = sha256_hex(image_bytes)
    if not image_digest:
        return {"decision": "image_bytes_required"}

    manifest_core = {
        "build_id": build_id,
        "source_digest": source_digest,
        "deps_lock_digest": deps_lock_digest,
        "dependencies": deps,
        "compiler_id": compiler_id,
        "compiler_digest": compiler_digest,
        "params_digest": params_digest,
        "params": params,
        "image_digest": image_digest,
        "signer": signer,
    }
    manifest_digest = digest_json(manifest_core)

    existing = _row(db, "SELECT * FROM ir_manifests WHERE build_id=?", (build_id,))
    if existing:
        if existing["manifest_digest"] != manifest_digest:
            return {
                "decision": "manifest_identity_conflict",
                "build_id": build_id,
                "pinned_manifest_digest": existing["manifest_digest"],
                "offered_manifest_digest": manifest_digest,
            }
        return {"decision": "manifest_pinned", "build_id": build_id,
                "manifest_digest": manifest_digest, "image_digest": image_digest,
                "idempotent": True}

    db.execute(
        "INSERT INTO ir_manifests VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
        (build_id, source_digest, deps_lock_digest, canonical(deps).decode(),
         compiler_id, compiler_digest, params_digest, canonical(params).decode(),
         image_digest, manifest_digest, signer, int(at)),
    )
    _commit(db)
    return {
        "decision": "manifest_pinned",
        "build_id": build_id,
        "source_digest": source_digest,
        "deps_lock_digest": deps_lock_digest,
        "compiler_digest": compiler_digest,
        "params_digest": params_digest,
        "image_digest": image_digest,
        "manifest_digest": manifest_digest,
    }


def verify_manifest_inputs(db, build_id, *, image_bytes=None, source_bytes=None,
                           dependencies=None, compiler_bytes=None, params=None):
    """Recompute pins from *actual* supplied inputs and compare to the manifest."""
    _ensure(db)
    m = _row(db, "SELECT * FROM ir_manifests WHERE build_id=?", (build_id,))
    if not m:
        return {"decision": "unknown_manifest", "build_id": build_id}

    checks = {}
    mismatches = []

    if source_bytes is not None:
        ok = sha256_hex(source_bytes) == m["source_digest"]
        checks["source"] = ok
        if not ok:
            mismatches.append("source_digest")

    if image_bytes is not None:
        ok = sha256_hex(image_bytes) == m["image_digest"]
        checks["image_bytes"] = ok
        if not ok:
            mismatches.append("image_digest")

    if compiler_bytes is not None:
        ok = sha256_hex(compiler_bytes) == m["compiler_digest"]
        checks["compiler"] = ok
        if not ok:
            mismatches.append("compiler_digest")

    if params is not None:
        ok = digest_json(dict(params)) == m["params_digest"]
        checks["params"] = ok
        if not ok:
            mismatches.append("params_digest")

    if dependencies is not None:
        offered = _normalise_deps(dependencies)
        pinned = json.loads(m["deps_json"])
        pinned_map = {(d["name"], d["version"]): d["digest"] for d in pinned}
        dep_ok = True
        dep_findings = []
        for d in offered:
            key = (d["name"], d["version"])
            if key not in pinned_map:
                dep_ok = False
                dep_findings.append({"dependency": d["name"], "reason": "unpinned_dependency"})
            elif pinned_map[key] != d["digest"]:
                dep_ok = False
                dep_findings.append({
                    "dependency": d["name"], "version": d["version"],
                    "reason": "dependency_digest_mismatch",
                    "pinned_digest": pinned_map[key], "observed_digest": d["digest"],
                })
        checks["dependencies"] = dep_ok
        if not dep_ok:
            mismatches.append("dependencies")
        result = {
            "decision": "manifest_verified" if not mismatches else "manifest_mismatch",
            "build_id": build_id, "checks": checks, "mismatches": mismatches,
        }
        if dep_findings:
            result["dependency_findings"] = dep_findings
        return result

    return {
        "decision": "manifest_verified" if not mismatches else "manifest_mismatch",
        "build_id": build_id, "checks": checks, "mismatches": mismatches,
    }


def attest_reproduction(db, reproduction_id, build_id, machine_id, at, *,
                        candidate_bytes=None, claimed_image_digest=None,
                        log_claims_identical=False):
    """Record a rebuild/reproduction claim.

    Logs and claimed digest strings never prove byte identity: without the real
    candidate bytes the attestation is recorded ``log_claim_insufficient``.
    """
    _ensure(db)
    m = _row(db, "SELECT image_digest FROM ir_manifests WHERE build_id=?", (build_id,))
    if not m:
        return {"decision": "unknown_manifest", "build_id": build_id}
    pinned = m["image_digest"]

    if candidate_bytes is None:
        observed = claimed_image_digest
        status = "log_claim_insufficient"
        decision = "log_claim_insufficient"
    else:
        observed = sha256_hex(candidate_bytes)
        if observed == pinned:
            status, decision = "byte_identical", "reproduction_identical"
        else:
            status, decision = "byte_differs", "reproduction_differs"

    db.execute("INSERT INTO ir_reproductions VALUES(?,?,?,?,?,?,?,?)",
               (reproduction_id, build_id, machine_id, int(at),
                "bytes" if candidate_bytes is not None else "log_only",
                pinned, observed, status))
    _commit(db)
    return {"decision": decision, "reproduction_id": reproduction_id,
            "status": status, "pinned_digest": pinned, "observed_digest": observed,
            "log_claims_identical": bool(log_claims_identical)}


# ---------------------------------------------------------------------------
# signing / scope / validity
# ---------------------------------------------------------------------------

def _normalise_scope(scope=None, customers=None, all_customers=False, actions=None):
    if scope is not None:
        customers = scope.get("customers")
        all_customers = scope.get("all_customers", False) or customers == "*"
        actions = scope.get("actions")
    customer_list = None if all_customers or customers == "*" else list(customers or [])
    return {
        "customers": sorted(customer_list) if customer_list is not None else None,
        "actions": sorted(actions) if actions else None,
    }


def _scope_covers(scope_json, customer, action):
    scope = json.loads(scope_json) if isinstance(scope_json, str) else scope_json
    if scope.get("customers") is not None and customer not in scope["customers"]:
        return False
    if scope.get("actions") is not None and action not in scope["actions"]:
        return False
    return True


def _time_reason(not_before, expires_at, at):
    if at < not_before:
        return "signature_not_yet_valid"
    if at > expires_at:
        return "signature_expired"
    return None


def _release_signing_payload(r):
    return {
        "id": r["id"], "build_id": r["build_id"],
        "manifest_digest": r["manifest_digest"], "image_digest": r["image_digest"],
        "mode": r["mode"], "customer": r["customer"], "tenant": r["tenant"],
        "scope": json.loads(r["scope_json"]), "signer": r["signer"],
        "issued_at": r["issued_at"], "not_before": r["not_before"],
        "expires_at": r["expires_at"],
    }


def publish_release(db, release_id, *, build_id, signer,
                    at=0, not_before=None, expires_at=None,
                    mode="common", customer=None, tenant=None,
                    customers=None, all_customers=False, scope=None, actions=None,
                    secret=None):
    """Sign a pinned manifest into an installable release with scope + validity."""
    _ensure(db)
    m = _row(db, "SELECT * FROM ir_manifests WHERE build_id=?", (build_id,))
    if not m:
        return {"decision": "unknown_manifest", "build_id": build_id}
    if m["signer"] != signer:
        return {"decision": "signer_not_pinned_subject",
                "pinned_signer": m["signer"], "offered_signer": signer}

    signer_row = _row(db, "SELECT secret FROM ir_signers WHERE subject=?", (signer,))
    if not signer_row and secret is None:
        return {"decision": "untrusted_signer", "signer": signer}
    key_secret = secret if secret is not None else signer_row["secret"]

    if mode not in ("common", "dedicated"):
        return {"decision": "invalid_release_mode", "mode": mode}
    if mode == "dedicated" and not customer:
        return {"decision": "dedicated_release_requires_customer"}

    nb = int(at if not_before is None else not_before)
    exp = int(expires_at if expires_at is not None else at + 365 * 24 * 3600)
    norm_scope = _normalise_scope(
        scope=scope, customers=customers, all_customers=all_customers, actions=actions
    )
    if mode == "dedicated":
        norm_scope["customers"] = [customer]

    payload = {
        "id": release_id, "build_id": build_id,
        "manifest_digest": m["manifest_digest"], "image_digest": m["image_digest"],
        "mode": mode, "customer": customer, "tenant": tenant,
        "scope": norm_scope, "signer": signer,
        "issued_at": int(at), "not_before": nb, "expires_at": exp,
    }
    signature = _mac(key_secret, payload)

    existing = _row(db, "SELECT id FROM ir_releases WHERE id=?", (release_id,))
    if existing:
        return {"decision": "release_identity_conflict", "release_id": release_id}

    db.execute(
        "INSERT INTO ir_releases(id,build_id,manifest_digest,image_digest,mode,customer,"
        "tenant,scope_json,signer,signature,issued_at,not_before,expires_at,state) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?, 'published')",
        (release_id, build_id, m["manifest_digest"], m["image_digest"], mode, customer,
         tenant, canonical(norm_scope).decode(), signer, signature, int(at), nb, exp),
    )
    _commit(db)
    return {"decision": "release_published", "release_id": release_id,
            "image_digest": m["image_digest"], "manifest_digest": m["manifest_digest"],
            "mode": mode, "signature": signature, "expires_at": exp}


def evaluate_release(db, release, at, *, customer=None, action=None, check_state=False):
    """Return a machine-readable reason string if the release fails validation."""
    if not release:
        return "unknown_release"
    signer_row = _row(db, "SELECT secret FROM ir_signers WHERE subject=?",
                      (release["signer"],))
    if not signer_row:
        return "untrusted_signer"
    expected = _mac(signer_row["secret"], _release_signing_payload(release))
    if not _same_sig(expected, release["signature"]):
        return "bad_signature"
    time_reason = _time_reason(release["not_before"], release["expires_at"], at)
    if time_reason:
        return time_reason
    if customer is not None and not _scope_covers(release["scope_json"], customer, action):
        return "outside_authorization_scope"
    if check_state and release["state"] == "withdrawn" and (
        release["withdrawn_at"] is None or release["withdrawn_at"] <= at
    ):
        return "release_withdrawn"
    return None


def verify_release(db, release_id, at, *, customer=None, action=None,
                   artifact_bytes=None, check_state=False):
    _ensure(db)
    r = _row(db, "SELECT * FROM ir_releases WHERE id=?", (release_id,))
    if not r:
        return {"decision": "unknown_release", "release_id": release_id}
    reason = evaluate_release(db, r, at, customer=customer, action=action,
                              check_state=check_state)
    if reason:
        return {"decision": reason, "release_id": release_id}
    if artifact_bytes is not None and sha256_hex(artifact_bytes) != r["image_digest"]:
        return {"decision": "artifact_bytes_mismatch", "release_id": release_id,
                "expected_digest": r["image_digest"],
                "observed_digest": sha256_hex(artifact_bytes)}
    return {"decision": "release_valid", "release_id": release_id,
            "image_digest": r["image_digest"]}


# ---------------------------------------------------------------------------
# per-customer signed configuration (keys + tenant policy), independently
# issued / rotated / revoked in the common-binary architecture
# ---------------------------------------------------------------------------

def issue_config(db, config_id, *, customer, signer, at=0,
                 customer_key=None, policy=None, config=None, tenant=None,
                 expires_at=None, not_before=None, grace_until=None,
                 generation=None, replaces=None, secret=None):
    _ensure(db)
    if config is None:
        config = {"customer": customer}
        if tenant is not None:
            config["tenant"] = tenant
        if customer_key is not None:
            config["customer_key"] = customer_key
        if policy is not None:
            config["policy"] = policy
    config.setdefault("customer", customer)

    signer_row = _row(db, "SELECT secret FROM ir_signers WHERE subject=?", (signer,))
    if not signer_row and secret is None:
        return {"decision": "untrusted_signer", "signer": signer}
    key_secret = secret if secret is not None else signer_row["secret"]

    if generation is None:
        prev = _row(db, "SELECT MAX(generation) g FROM ir_configs WHERE customer=?",
                    (customer,))
        generation = (prev["g"] or 0) + 1
    if replaces is None and generation > 1:
        old = _row(db, "SELECT id FROM ir_configs WHERE customer=? AND generation=?",
                   (customer, generation - 1))
        replaces = old["id"] if old else None

    config_digest = digest_json(config)
    nb = int(at if not_before is None else not_before)
    exp = int(expires_at if expires_at is not None else at + 365 * 24 * 3600)
    # Signature covers immutable config identity.  Lifecycle metadata
    # (state / rotation overlap) is attested separately and must not mutate
    # these bytes after signing.
    payload = {
        "id": config_id, "customer": customer, "tenant": tenant,
        "generation": generation, "config_digest": config_digest,
        "config": config, "signer": signer, "issued_at": int(at),
        "not_before": nb, "expires_at": exp,
        "replaces": replaces,
    }
    signature = _mac(key_secret, payload)

    db.execute(
        "INSERT INTO ir_configs(id,customer,tenant,generation,config_digest,config_json,"
        "signer,signature,issued_at,not_before,expires_at,grace_until,state,replaces) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?, 'active',?)",
        (config_id, customer, tenant, generation, config_digest,
         canonical(config).decode(), signer, signature, int(at), nb, exp,
         grace_until, replaces),
    )
    _commit(db)
    return {"decision": "config_issued", "config_id": config_id,
            "config_digest": config_digest, "generation": generation,
            "signature": signature}


def _config_signing_payload(c):
    return {
        "id": c["id"], "customer": c["customer"], "tenant": c["tenant"],
        "generation": c["generation"], "config_digest": c["config_digest"],
        "config": json.loads(c["config_json"]), "signer": c["signer"],
        "issued_at": c["issued_at"], "not_before": c["not_before"],
        "expires_at": c["expires_at"],
        "replaces": c["replaces"],
    }


def verify_config(db, *, at, customer=None, config_id=None, config_digest=None):
    _ensure(db)
    if config_id is not None:
        c = _row(db, "SELECT * FROM ir_configs WHERE id=?", (config_id,))
    else:
        c = _row(db, "SELECT * FROM ir_configs WHERE config_digest=? AND customer=?",
                 (config_digest, customer))
    if not c:
        return None, "unknown_config"

    signer_row = _row(db, "SELECT secret FROM ir_signers WHERE subject=?", (c["signer"],))
    if not signer_row:
        return c, "untrusted_config_signer"
    if not _same_sig(_mac(signer_row["secret"], _config_signing_payload(c)),
                     c["signature"]):
        return c, "bad_config_signature"

    time_reason = _time_reason(c["not_before"], c["expires_at"], at)
    if time_reason:
        return c, ("config_" + time_reason)

    if c["state"] == "revoked":
        return c, "config_revoked"
    if c["state"] == "rotated":
        grace_until = c["grace_until"]
        rotation = _row(db, "SELECT * FROM ir_config_rotations WHERE old_config_id=?",
                        (c["id"],))
        if rotation:
            rot_signer = _row(db, "SELECT secret FROM ir_signers WHERE subject=?",
                              (rotation["signer"],))
            new_cfg = _row(db, "SELECT config_digest FROM ir_configs WHERE id=?",
                           (rotation["new_config_id"],))
            rot_payload = {
                "kind": "key_rotation", "old_config_id": rotation["old_config_id"],
                "new_config_id": rotation["new_config_id"],
                "customer": rotation["customer"], "at": rotation["at"],
                "grace_until": rotation["grace_until"],
                "new_config_digest": new_cfg["config_digest"] if new_cfg else None,
            }
            if not rot_signer or not _same_sig(
                    _mac(rot_signer["secret"], rot_payload),
                    rotation["signature"]):
                return c, "bad_rotation_receipt"
            grace_until = rotation["grace_until"]
        # Previous generation stays usable only through the committed, signed
        # overlap window, bridging an offline device to the rotated key.
        if grace_until is None or at > grace_until:
            return c, "config_rotation_overlap_ended"
    if customer is not None and c["customer"] != customer:
        return c, "config_customer_mismatch"
    return c, None


def rotate_customer_key(db, new_config_id, *, customer, signer, at,
                        new_key=None, expires_at, overlap_until,
                        tenant=None, policy=None, secret=None):
    """Rotate a customer key with an overlap window for offline devices."""
    _ensure(db)
    old = _row(
        db,
        "SELECT * FROM ir_configs WHERE customer=? ORDER BY generation DESC LIMIT 1",
        (customer,),
    )
    if not old:
        return {"decision": "unknown_customer_config", "customer": customer}

    old_config = json.loads(old["config_json"])
    if new_key is None:
        new_key = "rotated-key-" + sha256_hex(old["config_digest"] + str(at))[:16]
    new_config = dict(old_config)
    new_config["customer_key"] = new_key
    new_config["key_rotated_at"] = at
    if policy is not None:
        new_config["policy"] = policy
    if tenant is None:
        tenant = old["tenant"]

    db.execute("UPDATE ir_configs SET state='rotated', grace_until=? WHERE id=?",
               (int(overlap_until), old["id"]))
    issued = issue_config(
        db, new_config_id, customer=customer, signer=signer, at=at,
        config=new_config, tenant=tenant, expires_at=expires_at,
        not_before=at, grace_until=None, generation=old["generation"] + 1,
        replaces=old["id"], secret=secret,
    )
    if issued.get("decision") != "config_issued":
        return issued

    signer_row = _row(db, "SELECT secret FROM ir_signers WHERE subject=?", (signer,))
    key_secret = secret if secret is not None else (
        signer_row["secret"] if signer_row else None)
    rotation_payload = {
        "kind": "key_rotation", "old_config_id": old["id"],
        "new_config_id": new_config_id, "customer": customer, "at": int(at),
        "grace_until": int(overlap_until),
        "new_config_digest": issued["config_digest"],
    }
    rotation_sig = _mac(key_secret, rotation_payload) if key_secret else None
    db.execute("INSERT OR REPLACE INTO ir_config_rotations VALUES(?,?,?,?,?,?,?)",
               (old["id"], new_config_id, customer, int(at),
                int(overlap_until), signer, rotation_sig))
    _commit(db)
    issued.update({
        "decision": "customer_key_rotated",
        "previous_config_id": old["id"],
        "previous_key_valid_until": int(overlap_until),
        "new_key": new_key,
        "rotation_signature": rotation_sig,
    })
    return issued


def revoke_config(db, config_id, at=None):
    _ensure(db)
    c = _row(db, "SELECT id FROM ir_configs WHERE id=?", (config_id,))
    if not c:
        return {"decision": "unknown_config", "config_id": config_id}
    db.execute("UPDATE ir_configs SET state='revoked' WHERE id=?", (config_id,))
    _commit(db)
    return {"decision": "config_revoked", "config_id": config_id}


# ---------------------------------------------------------------------------
# orders, verified downloads, install attempts
# ---------------------------------------------------------------------------

def open_order(db, order_id, *, customer, device_id, release_id, at=0,
               config_id=None, original_delivery_id=None, replacement_for=None):
    _ensure(db)
    r = _row(db, "SELECT * FROM ir_releases WHERE id=?", (release_id,))
    if not r:
        return {"decision": "unknown_release", "release_id": release_id}
    device = _row(db, "SELECT customer FROM ir_devices WHERE id=?", (device_id,))
    if not device:
        return {"decision": "unknown_device", "device_id": device_id}
    if device["customer"] != customer:
        return {"decision": "device_customer_mismatch"}

    expected_config_digest = None
    if config_id is not None:
        c = _row(db, "SELECT config_digest,customer FROM ir_configs WHERE id=?",
                 (config_id,))
        if not c:
            return {"decision": "unknown_config", "config_id": config_id}
        if c["customer"] != customer:
            return {"decision": "config_customer_mismatch"}
        expected_config_digest = c["config_digest"]

    if _row(db, "SELECT id FROM ir_orders WHERE id=?", (order_id,)):
        return {"decision": "order_identity_conflict", "order_id": order_id}

    db.execute(
        "INSERT INTO ir_orders(id,customer,device_id,release_id,build_id,mode,"
        "expected_image_digest,expected_config_digest,original_delivery_id,"
        "replacement_for,state,created_at) VALUES(?,?,?,?,?,?,?,?,?,?, 'opened',?)",
        (order_id, customer, device_id, release_id, r["build_id"], r["mode"],
         r["image_digest"], expected_config_digest, original_delivery_id,
         replacement_for, int(at)),
    )
    _commit(db)
    return {"decision": "order_opened", "order_id": order_id,
            "expected_image_digest": r["image_digest"]}


def record_download(db, download_id, order_id, at, *,
                    artifact_bytes=None, actual_digest=None):
    """Customer receives the installer: hash real bytes and validate signature,
    validity window and authorisation scope.  Never accepts the delivery."""
    _ensure(db)
    o = _row(db, "SELECT * FROM ir_orders WHERE id=?", (order_id,))
    if not o:
        return {"decision": "unknown_order", "order_id": order_id}
    r = _row(db, "SELECT * FROM ir_releases WHERE id=?", (o["release_id"],))

    if artifact_bytes is not None:
        actual_digest = sha256_hex(artifact_bytes)
    if not actual_digest:
        return {"decision": "download_bytes_required"}

    reason = evaluate_release(db, r, at, customer=o["customer"],
                              action="download", check_state=True)
    if reason is None and actual_digest != o["expected_image_digest"]:
        reason = "artifact_bytes_mismatch"

    state = "verified" if reason is None else "rejected"
    db.execute("INSERT INTO ir_downloads VALUES(?,?,?,?,?,?)",
               (download_id, order_id, int(at), actual_digest, state, reason))
    if reason is None and o["state"] == "opened":
        db.execute("UPDATE ir_orders SET state='downloaded' WHERE id=?", (order_id,))
    _commit(db)
    if reason:
        return {"decision": reason, "download_id": download_id,
                "expected_digest": o["expected_image_digest"],
                "actual_digest": actual_digest}
    return {"decision": "download_verified", "download_id": download_id,
            "order_state": "downloaded", "actual_digest": actual_digest}


def _cache_scope_for(order_or_release, customer=None):
    mode = order_or_release["mode"]
    cust = customer or order_or_release["customer"]
    if mode == "common":
        return "shared"
    return f"customer:{cust}"


def attempt_install(db, attempt_id, order_id, coordinate, at, *,
                    bundle_id=None, device_id=None):
    """Verify the cache-resolved bytes and revocation state before install.

    This is the gate that keeps a poisoned shared cache or a withdrawn digest
    from producing new installations.
    """
    _ensure(db)
    o = _row(db, "SELECT * FROM ir_orders WHERE id=?", (order_id,))
    if not o:
        return {"decision": "unknown_order", "order_id": order_id}
    device_id = device_id or o["device_id"]
    if device_id != o["device_id"]:
        return _record_install_block(db, attempt_id, o, device_id, at, coordinate,
                                     None, bundle_id, "install_device_mismatch")

    scope = _cache_scope_for(o, o["customer"])
    alias = _row(db, "SELECT * FROM ir_cache_aliases WHERE scope=? AND coordinate=?",
                 (scope, coordinate))
    if not alias:
        return _record_install_block(db, attempt_id, o, device_id, at, coordinate,
                                     None, bundle_id, "coordinate_not_in_cache")
    if alias["state"] == "poisoned":
        return _record_install_block(db, attempt_id, o, device_id, at, coordinate,
                                     alias["digest"], bundle_id, "cache_coordinate_poisoned")

    entry = _row(db, "SELECT * FROM ir_cache_entries WHERE scope=? AND digest=?",
                 (scope, alias["digest"]))
    if not entry:
        return _record_install_block(db, attempt_id, o, device_id, at, coordinate,
                                     alias["digest"], bundle_id, "cache_entry_missing")
    if entry["quarantined"]:
        return _record_install_block(db, attempt_id, o, device_id, at, coordinate,
                                     entry["digest"], bundle_id, "cache_entry_quarantined")

    actual_digest = sha256_hex(entry["blob"] or b"")
    if actual_digest != entry["digest"]:
        db.execute("UPDATE ir_cache_entries SET quarantined=1 WHERE scope=? AND digest=?",
                   (scope, entry["digest"]))
        _commit(db)
        return _record_install_block(db, attempt_id, o, device_id, at, coordinate,
                                     entry["digest"], bundle_id, "cache_blob_corrupt")

    resolved_digest = actual_digest

    # Revocation fence: live release state plus any signed offline bundle the
    # device was able to present.
    withdrawn = _is_digest_withdrawn(db, resolved_digest, at, bundle_id, device_id)
    if withdrawn:
        return _record_install_block(db, attempt_id, o, device_id, at, coordinate,
                                     resolved_digest, bundle_id,
                                     "install_blocked_withdrawn")

    r = _row(db, "SELECT * FROM ir_releases WHERE id=?", (o["release_id"],))
    reason = evaluate_release(db, r, at, customer=o["customer"], action="install",
                              check_state=True)
    if reason:
        return _record_install_block(db, attempt_id, o, device_id, at, coordinate,
                                     resolved_digest, bundle_id, reason)

    if resolved_digest != o["expected_image_digest"]:
        # Coordinate serves different real bytes than the signed order: classic
        # polluted-cache / download-vs-install divergence.
        db.execute("UPDATE ir_cache_aliases SET state='poisoned' WHERE scope=? AND coordinate=?",
                   (scope, coordinate))
        _commit(db)
        return _record_install_block(db, attempt_id, o, device_id, at, coordinate,
                                     resolved_digest, bundle_id, "cache_coordinate_mismatch")

    db.execute("INSERT INTO ir_install_attempts VALUES(?,?,?,?,?,?,?,?,?)",
               (attempt_id, order_id, device_id, int(at), coordinate,
                resolved_digest, bundle_id, "verified", None))
    _commit(db)
    return {"decision": "install_verified", "attempt_id": attempt_id,
            "digest": resolved_digest, "scope": scope}


def _record_install_block(db, attempt_id, o, device_id, at, coordinate,
                          resolved_digest, bundle_id, reason):
    db.execute("INSERT INTO ir_install_attempts VALUES(?,?,?,?,?,?,?,?,?)",
               (attempt_id, o["id"], device_id, int(at), coordinate,
                resolved_digest, bundle_id, "blocked", reason))
    _commit(db)
    return {"decision": reason, "attempt_id": attempt_id,
            "order_id": o["id"], "resolved_digest": resolved_digest}


def _is_digest_withdrawn(db, image_digest, at, bundle_id=None, device_id=None):
    row = _row(
        db,
        "SELECT 1 x FROM ir_releases WHERE image_digest=? AND state='withdrawn' "
        "AND withdrawn_at IS NOT NULL AND withdrawn_at<=? LIMIT 1",
        (image_digest, at),
    )
    if row:
        return True
    # Signed revocation bundle (possibly staged out-of-band for an offline
    # device) can fence the digest even before live state is reachable.
    bundle_ids = []
    if bundle_id:
        bundle_ids.append(bundle_id)
    if device_id:
        for r in db.execute("SELECT bundle_id FROM ir_device_evidence WHERE device_id=?",
                            (device_id,)):
            bundle_ids.append(r["bundle_id"])
    for bid in set(bundle_ids):
        b = _row(db, "SELECT * FROM ir_bundles WHERE id=?", (bid,))
        if not b or at > b["expires_at"]:
            continue
        payload = json.loads(b["payload_json"])
        if image_digest in payload.get("withdrawn_digests", []):
            return True
    return False


# ---------------------------------------------------------------------------
# device boot measurement receipts
# ---------------------------------------------------------------------------

def attest_measurement(device_secret, *, device_id, boot_id, image_digest,
                       at, config_digest=None):
    """Produce the HMAC receipt a real device would sign after boot."""
    payload = {
        "kind": "boot_measurement", "device_id": device_id, "boot_id": boot_id,
        "image_digest": image_digest, "config_digest": config_digest, "at": int(at),
    }
    return _mac(device_secret, payload)


def record_measurement(db, measurement_id, device_id, at, image_digest, *,
                       boot_id=None, config_digest=None, signature=None,
                       order_id=None):
    _ensure(db)
    d = _row(db, "SELECT * FROM ir_devices WHERE id=?", (device_id,))
    if not d:
        return {"decision": "unknown_device", "device_id": device_id}

    payload = {
        "kind": "boot_measurement", "device_id": device_id, "boot_id": boot_id,
        "image_digest": image_digest, "config_digest": config_digest, "at": int(at),
    }
    verified = bool(signature) and _same_sig(_mac(d["secret"], payload), signature)
    state = "recorded" if verified else "invalid_attestation"

    db.execute("INSERT INTO ir_measurements VALUES(?,?,?,?,?,?,?,?,?,?)",
               (measurement_id, device_id, order_id, int(at), image_digest,
                config_digest, boot_id, signature, 1 if verified else 0, state))
    db.execute("UPDATE ir_devices SET last_seen=? WHERE id=?", (int(at), device_id))
    _commit(db)
    if not verified:
        return {"decision": "measurement_attestation_invalid",
                "measurement_id": measurement_id}
    return {"decision": "measurement_recorded", "measurement_id": measurement_id,
            "device_id": device_id, "image_digest": image_digest,
            "config_digest": config_digest}


def latest_measurement(db, device_id, only_verified=True):
    _ensure(db)
    sql = "SELECT * FROM ir_measurements WHERE device_id=?"
    if only_verified:
        sql += " AND verified=1"
    sql += " ORDER BY at DESC, rowid DESC LIMIT 1"
    return _row(db, sql, (device_id,))


# ---------------------------------------------------------------------------
# customer acceptance — the only thing that completes delivery
# ---------------------------------------------------------------------------

def accept_delivery(db, acceptance_id, order_id, at, *,
                    measurement_id=None, approved_config_digest=None,
                    customer=None):
    _ensure(db)
    prior_id = _row(db, "SELECT * FROM ir_acceptances WHERE id=?", (acceptance_id,))
    if prior_id:
        return {"decision": ("delivery_accepted" if prior_id["state"] == "accepted"
                            else prior_id["reason"] or "acceptance_rejected"),
                "acceptance_id": acceptance_id, "order_id": prior_id["order_id"],
                "idempotent": True}
    o = _row(db, "SELECT * FROM ir_orders WHERE id=?", (order_id,))
    if not o:
        return {"decision": "unknown_order", "order_id": order_id}
    if customer is not None and customer != o["customer"]:
        return {"decision": "acceptance_customer_mismatch"}

    prior = _row(db, "SELECT * FROM ir_acceptances WHERE order_id=? AND state='accepted'",
                 (order_id,))
    if prior:
        return {"decision": "delivery_accepted", "acceptance_id": prior["id"],
                "order_id": order_id, "idempotent": True}

    def reject(reason, mid=None):
        db.execute("INSERT INTO ir_acceptances VALUES(?,?,?,?,?,?,?,?)",
                   (acceptance_id, order_id, mid, o["customer"], int(at),
                    approved_config_digest, "rejected", reason))
        _commit(db)
        return {"decision": reason, "acceptance_id": acceptance_id, "order_id": order_id}

    r = _row(db, "SELECT * FROM ir_releases WHERE id=?", (o["release_id"],))

    # Withdrawal fence comes first: a late acceptance must never revive a
    # withdrawn release or move the per-customer current pointer.
    if r["state"] == "withdrawn" and r["withdrawn_at"] is not None and r["withdrawn_at"] <= at:
        return reject("acceptance_blocked_withdrawn", measurement_id)

    reason = evaluate_release(db, r, at, customer=o["customer"], action="accept")
    if reason:
        return reject(reason, measurement_id)

    download = _row(
        db,
        "SELECT 1 x FROM ir_downloads WHERE order_id=? AND state='verified' LIMIT 1",
        (order_id,),
    )
    if not download:
        return reject("verified_download_required", measurement_id)

    if measurement_id is None:
        m = latest_measurement(db, o["device_id"])
    else:
        m = _row(db, "SELECT * FROM ir_measurements WHERE id=?", (measurement_id,))
    if not m:
        return reject("device_measurement_required")
    if not m["verified"]:
        return reject("measurement_attestation_invalid", m["id"])
    if m["device_id"] != o["device_id"]:
        return reject("measurement_device_mismatch", m["id"])
    if m["image_digest"] != o["expected_image_digest"]:
        return reject("measurement_digest_mismatch", m["id"])

    if approved_config_digest is None:
        # In the dedicated architecture the approved image/manifest digest *is*
        # the embedded policy identity, so a separate config envelope is
        # optional.  Common-binary deliveries always require one, and any
        # measurement that carries a config digest requires approval + check.
        config_required = (
            o["mode"] == "common"
            or bool(o["expected_config_digest"])
            or m["config_digest"] is not None
        )
        if config_required:
            return reject("approved_config_identity_required", m["id"])
    if approved_config_digest is not None or m["config_digest"] is not None \
            or o["expected_config_digest"]:
        if approved_config_digest is None:
            return reject("approved_config_identity_required", m["id"])
        if m["config_digest"] != approved_config_digest:
            return reject("measurement_config_mismatch", m["id"])
        if o["expected_config_digest"] and approved_config_digest != o["expected_config_digest"]:
            return reject("approved_config_not_on_order", m["id"])

        _c, config_reason = verify_config(db, at=at, customer=o["customer"],
                                          config_digest=approved_config_digest)
        if config_reason:
            return reject(config_reason, m["id"])

    db.execute("INSERT INTO ir_acceptances VALUES(?,?,?,?,?,?,?,?)",
               (acceptance_id, order_id, m["id"], o["customer"], int(at),
                approved_config_digest, "accepted", None))
    db.execute("UPDATE ir_orders SET state='accepted' WHERE id=?", (order_id,))
    db.execute(
        "INSERT INTO ir_customer_current(customer,current_release_id,"
        "current_image_digest,current_config_digest,accepted_order_id,updated_at) "
        "VALUES(?,?,?,?,?,?) ON CONFLICT(customer) DO UPDATE SET "
        "current_release_id=excluded.current_release_id,"
        "current_image_digest=excluded.current_image_digest,"
        "current_config_digest=excluded.current_config_digest,"
        "accepted_order_id=excluded.accepted_order_id,updated_at=excluded.updated_at",
        (o["customer"], o["release_id"], o["expected_image_digest"],
         approved_config_digest, order_id, int(at)),
    )
    # Resolve any open recovery case for this device/digest.
    db.execute(
        "UPDATE ir_recovery_cases SET fallback_release_id=fallback_release_id "
        "WHERE device_id=? AND measured_digest=?",
        (o["device_id"], o["expected_image_digest"]),
    )
    _commit(db)
    return {"decision": "delivery_accepted", "acceptance_id": acceptance_id,
            "order_id": order_id, "image_digest": o["expected_image_digest"],
            "config_digest": approved_config_digest}


def correct_order(db, correction_id, order_id, at, *, kind="runtime_drift",
                  observed_image_digest=None, measurement_id=None, note=None,
                  replacement_order_id=None, replacement_release_id=None,
                  replacement_config_id=None):
    """Append an immutable correction and optionally open the replacement order.

    The original order / provisional acceptance rows are never deleted: the
    customer really received those bytes, and the correction is the reviewable
    record that runtime identity differed.
    """
    _ensure(db)
    o = _row(db, "SELECT * FROM ir_orders WHERE id=?", (order_id,))
    if not o:
        return {"decision": "unknown_order", "order_id": order_id}

    new_order_id = None
    if replacement_order_id is not None:
        if replacement_release_id is None:
            return {"decision": "replacement_release_required"}
        opened = open_order(
            db, replacement_order_id, customer=o["customer"],
            device_id=o["device_id"], release_id=replacement_release_id, at=at,
            config_id=replacement_config_id, replacement_for=order_id,
        )
        if opened.get("decision") != "order_opened":
            return opened
        new_order_id = replacement_order_id

    db.execute("INSERT INTO ir_corrections VALUES(?,?,?,?,?,?,?,?)",
               (correction_id, order_id, int(at), kind, observed_image_digest,
                measurement_id, new_order_id, note))
    if o["state"] not in ("accepted",):
        db.execute("UPDATE ir_orders SET state='corrected' WHERE id=?", (order_id,))
    _commit(db)
    return {"decision": "order_corrected", "correction_id": correction_id,
            "order_id": order_id, "replacement_order_id": new_order_id,
            "preserved_order_state": o["state"]}


# ---------------------------------------------------------------------------
# revocation bundles for offline devices
# ---------------------------------------------------------------------------

def create_revocation_bundle(db, bundle_id, signer, at, expires_at, *,
                             release_ids=None, image_digests=None,
                             fallback_release_id=None, secret=None):
    _ensure(db)
    digests = set(image_digests or [])
    for rid in release_ids or []:
        r = _row(db, "SELECT image_digest FROM ir_releases WHERE id=?", (rid,))
        if r:
            digests.add(r["image_digest"])
    payload = {
        "kind": "revocation_bundle", "id": bundle_id,
        "withdrawn_digests": sorted(digests),
        "release_ids": list(release_ids or []),
        "fallback_release_id": fallback_release_id,
        "issued_at": int(at), "expires_at": int(expires_at),
    }
    signer_row = _row(db, "SELECT secret FROM ir_signers WHERE subject=?", (signer,))
    if not signer_row and secret is None:
        return {"decision": "untrusted_signer", "signer": signer}
    key_secret = secret if secret is not None else signer_row["secret"]
    signature = _mac(key_secret, payload)
    db.execute("INSERT INTO ir_bundles VALUES(?,?,?,?,?,?)",
               (bundle_id, signer, signature, int(at), int(expires_at),
                canonical(payload).decode()))
    _commit(db)
    return {"decision": "revocation_bundle_created", "bundle_id": bundle_id,
            "withdrawn_digests": sorted(digests)}


def stage_device_evidence(db, device_id, bundle_id, at):
    _ensure(db)
    if not _row(db, "SELECT id FROM ir_devices WHERE id=?", (device_id,)):
        return {"decision": "unknown_device", "device_id": device_id}
    if not _row(db, "SELECT id FROM ir_bundles WHERE id=?", (bundle_id,)):
        return {"decision": "unknown_bundle", "bundle_id": bundle_id}
    db.execute("INSERT OR REPLACE INTO ir_device_evidence VALUES(?,?,?)",
               (device_id, bundle_id, int(at)))
    _commit(db)
    return {"decision": "evidence_staged", "device_id": device_id,
            "bundle_id": bundle_id}


# ---------------------------------------------------------------------------
# withdrawal with fallback / window / offline-evidence atomic boundary
# ---------------------------------------------------------------------------

def _affected_devices(db, image_digest):
    """Latest authentic measurement per device currently running this digest."""
    out = []
    for dev in _rows(db, "SELECT id, customer, online FROM ir_devices"):
        m = latest_measurement(db, dev["id"])  # at DESC, rowid DESC tie-break
        if m and m["image_digest"] == image_digest:
            m = dict(m)
            m["customer"] = dev["customer"]
            m["device_customer"] = dev["customer"]
            m["device_online"] = dev["online"]
            out.append(m)
    return out


def _fallback_issues(db, fallback_release_id, at, customers):
    if not fallback_release_id:
        return [{"code": "fallback_release_required"}]
    f = _row(db, "SELECT * FROM ir_releases WHERE id=?", (fallback_release_id,))
    if not f:
        return [{"code": "fallback_release_missing", "release_id": fallback_release_id}]
    issues = []
    if f["state"] == "withdrawn":
        issues.append({"code": "fallback_release_withdrawn"})
    reason = evaluate_release(db, f, at, action="install")
    if reason:
        issues.append({"code": "fallback_" + reason})

    # Real fallback bytes must already be available in the cache partition the
    # affected customers install from; a pointer to a release is not recovery.
    scopes = (["shared"] if f["mode"] == "common"
              else [f"customer:{c}" for c in customers])
    found = False
    for scope in scopes:
        e = _row(db,
                 "SELECT * FROM ir_cache_entries WHERE scope=? AND digest=? "
                 "AND quarantined=0",
                 (scope, f["image_digest"]))
        if e and sha256_hex(e["blob"] or b"") == f["image_digest"]:
            found = True
            break
    if not found:
        issues.append({"code": "fallback_artifact_not_cached",
                       "image_digest": f["image_digest"], "scopes": scopes})

    for c in customers:
        if not _scope_covers(f["scope_json"], c, "install"):
            issues.append({"code": "fallback_scope_denied", "customer": c})
    return issues


def _device_has_accepted_fallback(db, device_id, fallback_release_id):
    if not fallback_release_id:
        return False
    row = _row(
        db,
        """
        SELECT 1 x FROM ir_acceptances a
        JOIN ir_orders o ON o.id = a.order_id
        WHERE a.state='accepted' AND o.device_id=? AND o.release_id=?
        LIMIT 1
        """,
        (device_id, fallback_release_id),
    )
    return bool(row)


def _normalise_windows(windows):
    window_map = {}
    for key, value in (windows or {}).items():
        if isinstance(value, dict):
            window_map[key] = int(value.get("run_until") or value.get("until"))
        else:
            window_map[key] = int(value)
    return window_map


def _withdrawal_readiness(db, r, at, *, fallback_release_id=None,
                          windows=None, device_evidence=None, bundle_id=None,
                          allow_without_affected=False):
    """All non-mutating checks shared by planning and atomic withdrawal."""
    affected = _affected_devices(db, r["image_digest"])
    customers = sorted({d["customer"] for d in affected})
    window_map = _normalise_windows(windows)
    device_evidence = device_evidence or {}

    fallback_issues = _fallback_issues(db, fallback_release_id, at, customers)
    issues = list(fallback_issues)

    evidence_issues = []
    window_issues = []
    for d in affected:
        c = d["customer"]
        if c not in window_map or window_map[c] < at:
            window_issues.append({"code": "business_window_required", "customer": c})
        if not d["device_online"]:
            bid = device_evidence.get(d["device_id"], bundle_id)
            staged = _row(db,
                          "SELECT bundle_id FROM ir_device_evidence WHERE device_id=? "
                          "ORDER BY staged_at DESC LIMIT 1",
                          (d["device_id"],))
            if not bid and staged:
                bid = staged["bundle_id"]
            if not bid:
                evidence_issues.append({
                    "code": "offline_revocation_evidence_missing",
                    "device_id": d["device_id"], "customer": c,
                })
            else:
                b = _row(db, "SELECT * FROM ir_bundles WHERE id=?", (bid,))
                if not b:
                    evidence_issues.append({"code": "unknown_bundle",
                                            "device_id": d["device_id"],
                                            "bundle_id": bid})
                elif at > b["expires_at"]:
                    evidence_issues.append({"code": "revocation_bundle_expired",
                                            "device_id": d["device_id"],
                                            "bundle_id": bid})
    issues.extend(window_issues)
    issues.extend(evidence_issues)

    accepted_issues = []
    if not fallback_issues and fallback_release_id:
        for d in affected:
            if not _device_has_accepted_fallback(db, d["device_id"],
                                                  fallback_release_id):
                accepted_issues.append({
                    "code": "accepted_fallback_required",
                    "device_id": d["device_id"], "customer": d["customer"],
                    "fallback_release_id": fallback_release_id,
                    "offline": not d["device_online"],
                })

    if not affected and not allow_without_affected and fallback_issues:
        issues.append({"code": "withdrawing_unmeasured_release_needs_fallback_or_flag"})

    return {
        "release": r, "affected": affected, "customers": customers,
        "window_map": window_map, "issues": issues,
        "fallback_issues": fallback_issues,
        "window_issues": window_issues,
        "evidence_issues": evidence_issues,
        "accepted_issues": accepted_issues,
        "committable": not issues,
        # Strict boundary used when tearing down a common program an offline
        # customer depends on: an available cached fallback is not enough;
        # that specific device must already have accepted it.
        "strict_committable": not issues and not accepted_issues,
    }


def plan_withdrawal(db, release_id, at, *, fallback_release_id=None,
                    windows=None, device_evidence=None, bundle_id=None,
                    allow_without_affected=False):
    """Reviewable, non-mutating atomic-boundary decision for a withdrawal."""
    _ensure(db)
    r = _row(db, "SELECT * FROM ir_releases WHERE id=?", (release_id,))
    if not r:
        return {"decision": "unknown_release", "release_id": release_id}
    if r["state"] == "withdrawn":
        return {"decision": "already_withdrawn", "release_id": release_id}
    ready = _withdrawal_readiness(
        db, r, at, fallback_release_id=fallback_release_id, windows=windows,
        device_evidence=device_evidence, bundle_id=bundle_id,
        allow_without_affected=allow_without_affected)
    return {
        "decision": "withdrawal_plan", "release_id": release_id, "at": at,
        "affected_devices": [d["device_id"] for d in ready["affected"]],
        "customers": ready["customers"],
        "committable": ready["committable"],
        "strict_committable": ready["strict_committable"],
        "issues": ready["issues"],
        "accepted_fallback_issues": ready["accepted_issues"],
        "boundary": (
            "arm_install_block_once_fallback_bytes_window_and_evidence_exist; "
            "declare_customer_safe_only_after_accepted_device_measurement_on_fallback"
        ),
    }


def withdraw_release(db, release_id, at, *, reason=None,
                     fallback_release_id=None, windows=None,
                     device_evidence=None, bundle_id=None,
                     allow_without_affected=False,
                     require_accepted_fallback=False):
    """Atomically fence new installs while preserving runtime facts.

    The withdrawal commits only when every device currently measured on the
    release has a viable fallback, a committed customer run window and — for
    offline devices — signed revocation evidence that can be staged for it.
    With ``require_accepted_fallback`` the affected device must already have an
    accepted delivery of the fallback (the safe ordering before revoking a
    common program an offline customer still depends on).  Otherwise nothing is
    withdrawn and the caller gets the blocking issues.
    """
    _ensure(db)
    r = _row(db, "SELECT * FROM ir_releases WHERE id=?", (release_id,))
    if not r:
        return {"decision": "unknown_release", "release_id": release_id}
    if r["state"] == "withdrawn":
        return {"decision": "already_withdrawn", "release_id": release_id,
                "withdrawn_at": r["withdrawn_at"]}

    ready = _withdrawal_readiness(
        db, r, at, fallback_release_id=fallback_release_id, windows=windows,
        device_evidence=device_evidence, bundle_id=bundle_id,
        allow_without_affected=allow_without_affected)
    affected = ready["affected"]
    customers = ready["customers"]
    window_map = ready["window_map"]

    # Strict ordering guard has its own distinct decision when it is the only
    # missing condition.
    if require_accepted_fallback and ready["accepted_issues"] \
            and not ready["issues"]:
        return {"decision": "withdrawal_blocked_unaccepted_fallback",
                "release_id": release_id,
                "issues": ready["accepted_issues"],
                "affected_devices": [d["device_id"] for d in affected]}

    if ready["issues"]:
        if ready["fallback_issues"]:
            decision = "withdrawal_blocked_fallback"
        elif ready["evidence_issues"]:
            decision = "withdrawal_blocked_offline_evidence"
        else:
            decision = "withdrawal_blocked_recovery"
        issues = list(ready["issues"])
        if require_accepted_fallback:
            issues.extend(ready["accepted_issues"])
        return {"decision": decision, "release_id": release_id, "issues": issues,
                "affected_devices": [d["device_id"] for d in affected]}

    # ---- commit point: validation above this line, writes below -----------
    db.execute(
        "UPDATE ir_releases SET state='withdrawn', withdrawn_at=?, "
        "withdraw_reason=?, fallback_release_id=? WHERE id=?",
        (int(at), reason, fallback_release_id, release_id),
    )
    db.execute("INSERT OR REPLACE INTO ir_withdrawals VALUES(?,?,?,?,?)",
               (release_id, int(at), reason, fallback_release_id, bundle_id))
    for c, until in window_map.items():
        db.execute("INSERT OR REPLACE INTO ir_windows VALUES(?,?,?,?)",
                   (release_id, c, until, None))
    for d in affected:
        bid = (device_evidence or {}).get(d["device_id"], bundle_id)
        if not bid:
            staged = _row(db,
                          "SELECT bundle_id FROM ir_device_evidence WHERE device_id=? "
                          "ORDER BY staged_at DESC LIMIT 1", (d["device_id"],))
            bid = staged["bundle_id"] if staged else None
        db.execute("INSERT OR REPLACE INTO ir_recovery_cases VALUES(?,?,?,?,?,?,?,?)",
                   (release_id, d["device_id"], d["customer"], d["image_digest"],
                    fallback_release_id, 0 if d["device_online"] else 1, bid,
                    window_map.get(d["customer"])))
    _commit(db)
    return {"decision": "release_withdrawn", "release_id": release_id,
            "fallback_release_id": fallback_release_id,
            "affected_devices": [d["device_id"] for d in affected],
            "customers": customers}


def withdrawal_progress(db, release_id, at=None):
    """Per-device recovery truth; withdrawal alone never means safe removal."""
    _ensure(db)
    r = _row(db, "SELECT * FROM ir_releases WHERE id=?", (release_id,))
    cases = _rows(db, "SELECT * FROM ir_recovery_cases WHERE release_id=?", (release_id,))
    device_results = []
    all_remediated = True
    for case in cases:
        dv = device_view(db, case["device_id"], at=at)
        remediated = bool(
            case["fallback_release_id"]
            and dv.get("latest_image_digest")
            and _release_digest(db, case["fallback_release_id"]) == dv["latest_image_digest"]
            and dv.get("accepted_current")
        )
        if not remediated:
            all_remediated = False
        device_results.append({
            "device_id": case["device_id"], "customer": case["customer"],
            "offline": bool(case["offline"]),
            "latest_image_digest": dv.get("latest_image_digest"),
            "state": dv.get("state"),
            "remediated": remediated,
            "evidence_id": case["evidence_id"],
            "window_until": case["window_until"],
        })
    return {
        "release_id": release_id,
        "release_state": r["state"] if r else "unknown",
        "devices": device_results,
        "all_devices_remediated": all_remediated,
        # "safely withdrawn" requires every formerly affected device to have a
        # fresh measurement on the accepted fallback.  An offline device still
        # running the old digest keeps this false.
        "safely_withdrawn": bool(cases) and all_remediated,
    }


def _release_digest(db, release_id):
    r = _row(db, "SELECT image_digest FROM ir_releases WHERE id=?", (release_id,))
    return r["image_digest"] if r else None


# ---------------------------------------------------------------------------
# per-device / per-customer truth (replaces the single global pointer)
# ---------------------------------------------------------------------------

def device_view(db, device_id, at=None):
    _ensure(db)
    d = _row(db, "SELECT * FROM ir_devices WHERE id=?", (device_id,))
    if not d:
        return {"device_id": device_id, "state": "unknown_device"}
    m = latest_measurement(db, device_id)
    current = _row(db, "SELECT * FROM ir_customer_current WHERE customer=?",
                   (d["customer"],))
    view = {
        "device_id": device_id, "customer": d["customer"],
        "online": bool(d["online"]), "last_seen": d["last_seen"],
        "latest_image_digest": m["image_digest"] if m else None,
        "latest_config_digest": m["config_digest"] if m else None,
        "measured_at": m["at"] if m else None,
        "accepted_current": False, "withdrawn_digest": False,
    }
    if not m:
        view["state"] = "no_measurement"
        return view

    withdrawn = _row(db,
                     "SELECT id release_id FROM ir_releases WHERE image_digest=? "
                     "AND state='withdrawn' LIMIT 1", (m["image_digest"],))
    view["withdrawn_digest"] = bool(withdrawn)
    matches_acceptance = bool(
        current and current["current_image_digest"] == m["image_digest"]
    )
    view["accepted_current"] = matches_acceptance and bool(
        current and current["current_config_digest"] == m["config_digest"]
    )

    if not d["online"]:
        if withdrawn or not view["accepted_current"]:
            view["state"] = "offline_old_version"
        else:
            view["state"] = "offline_accepted"
    elif withdrawn:
        view["state"] = "running_withdrawn"
    elif matches_acceptance and view["accepted_current"]:
        view["state"] = "accepted_current"
    elif current and not matches_acceptance:
        view["state"] = "runtime_drift"
    else:
        view["state"] = "measured_not_accepted"
    return view


def customer_view(db, customer, at=None):
    _ensure(db)
    current = _row(db, "SELECT * FROM ir_customer_current WHERE customer=?", (customer,))
    devices = _rows(db, "SELECT id FROM ir_devices WHERE customer=?", (customer,))
    device_views = [device_view(db, d["id"], at=at) for d in devices]
    offline_old = [v["device_id"] for v in device_views
                   if v["state"] == "offline_old_version"]
    return {
        "customer": customer,
        "current_release_id": current["current_release_id"] if current else None,
        "current_image_digest": current["current_image_digest"] if current else None,
        "current_config_digest": current["current_config_digest"] if current else None,
        "accepted_order_id": current["accepted_order_id"] if current else None,
        "devices": device_views,
        "offline_old_version_devices": offline_old,
        "all_devices_accepted_current": all(
            v["state"] == "accepted_current" for v in device_views
        ) and bool(device_views),
    }


def fleet_view(db, at=None):
    _ensure(db)
    customers = [r["customer"] for r in db.execute(
        "SELECT DISTINCT customer FROM ir_devices ORDER BY customer")]
    return {c: customer_view(db, c, at=at) for c in customers}


def set_global_latest(db, channel, release_id, at):
    _ensure(db)
    r = _row(db, "SELECT image_digest FROM ir_releases WHERE id=?", (release_id,))
    if not r:
        return {"decision": "unknown_release", "release_id": release_id}
    db.execute(
        "INSERT INTO ir_global_pointer(channel,release_id,image_digest,updated_at) "
        "VALUES(?,?,?,?) ON CONFLICT(channel) DO UPDATE SET "
        "release_id=excluded.release_id, image_digest=excluded.image_digest, "
        "updated_at=excluded.updated_at",
        (channel, release_id, r["image_digest"], int(at)),
    )
    _commit(db)
    return {"decision": "global_latest_set", "channel": channel,
            "release_id": release_id, "image_digest": r["image_digest"]}


def get_global_latest(db, channel="resolver"):
    _ensure(db)
    return _row(db, "SELECT * FROM ir_global_pointer WHERE channel=?", (channel,))


# ---------------------------------------------------------------------------
# content addressed cache with tenant partitions and leak / poison auditing
# ---------------------------------------------------------------------------

def cache_put_image(db, coordinate, blob, *, scope="shared", customer=None,
                    kind="image", at=0, sensitive_markers=None):
    """Store image bytes in a partitioned, content-addressed cache.

    The shared partition refuses customer key/config/policy material and scans
    the bytes for any already-registered customer secret.  Customer scoped
    partitions are named ``customer:<id>``.
    """
    _ensure(db)
    if isinstance(blob, str):
        blob = blob.encode("utf-8")
    if scope == "customer":
        if not customer:
            return {"decision": "customer_scope_requires_customer"}
        scope = f"customer:{customer}"
    if scope == "shared":
        if kind in CUSTOMER_MATERIAL_KINDS:
            return {"decision": "customer_material_in_shared_cache", "kind": kind}
        leak = _scan_markers(db, blob, extra_markers=sensitive_markers)
        if leak:
            return {"decision": "secret_material_in_shared_cache", "leaks": leak}

    digest = sha256_hex(blob)
    db.execute(
        "INSERT OR REPLACE INTO ir_cache_entries(scope,digest,kind,customer,blob,size,"
        "created_at,quarantined) VALUES(?,?,?,?,?,?,?,0)",
        (scope, digest, kind, customer, sqlite3.Binary(blob), len(blob), int(at)),
    )
    if coordinate:
        db.execute(
            "INSERT INTO ir_cache_aliases(scope,coordinate,digest,state) "
            "VALUES(?,?,?, 'clean') ON CONFLICT(scope,coordinate) "
            "DO UPDATE SET digest=excluded.digest, state='clean'",
            (scope, coordinate, digest),
        )
    _commit(db)
    return {"decision": "cache_stored", "scope": scope, "coordinate": coordinate,
            "digest": digest}


def cache_put_customer_material(db, coordinate, blob, *, customer, kind="customer_config",
                                at=0):
    """Customer keys / policies only ever land in that customer's partition."""
    return cache_put_image(db, coordinate, blob, scope=f"customer:{customer}",
                           customer=customer, kind=kind, at=at)


def _collect_markers(db, extra_markers=None):
    markers = []  # (label, bytes)
    for item in extra_markers or []:
        if isinstance(item, tuple):
            markers.append(item)
        else:
            markers.append(("supplied_marker", item if isinstance(item, bytes)
                             else str(item).encode()))
    for c in _rows(db, "SELECT customer,config_json FROM ir_configs"):
        try:
            cfg = json.loads(c["config_json"])
        except (TypeError, ValueError):
            continue
        key = cfg.get("customer_key")
        if key:
            markers.append((f"customer_key:{c['customer']}", str(key).encode()))
        policy = cfg.get("policy")
        if policy is not None:
            encoded = canonical(policy)
            if len(encoded) >= 8:
                markers.append((f"tenant_policy:{c['customer']}", encoded))
    # de-duplicate
    seen = set()
    out = []
    for label, marker in markers:
        if len(marker) < 8:
            continue
        if marker not in seen:
            seen.add(marker)
            out.append((label, marker))
    return out


def _scan_markers(db, blob, extra_markers=None):
    leaks = []
    for label, marker in _collect_markers(db, extra_markers):
        if marker and marker in (blob or b""):
            leaks.append({"marker": label})
    return leaks


def cache_get(db, coordinate_or_digest, *, scope="shared", customer=None,
              by="coordinate"):
    """Read with tenant partition enforcement and real-byte rehashing."""
    _ensure(db)
    if scope == "customer":
        scope = f"customer:{customer}"
    if scope != "shared":
        if not customer or scope != f"customer:{customer}":
            return {"decision": "cache_scope_denied"}

    if by == "coordinate":
        alias = _row(db, "SELECT * FROM ir_cache_aliases WHERE scope=? AND coordinate=?",
                     (scope, coordinate_or_digest))
        if not alias:
            return {"decision": "cache_coordinate_missing"}
        digest = alias["digest"]
        if alias["state"] == "poisoned":
            return {"decision": "cache_coordinate_poisoned", "digest": digest}
    else:
        digest = coordinate_or_digest

    entry = _row(db, "SELECT * FROM ir_cache_entries WHERE scope=? AND digest=?",
                 (scope, digest))
    if not entry:
        return {"decision": "cache_entry_missing", "digest": digest}
    if entry["quarantined"]:
        return {"decision": "cache_entry_quarantined", "digest": digest}
    if sha256_hex(entry["blob"] or b"") != digest:
        return {"decision": "cache_blob_corrupt", "digest": digest}
    return {"decision": "cache_hit", "digest": digest, "blob": entry["blob"],
            "scope": scope}


def cache_cross_tenant_get(db, digest, *, customer, other_customer):
    """A customer may not address another customer's partition."""
    _ensure(db)
    wanted = f"customer:{other_customer}"
    own = f"customer:{customer}"
    if wanted != own:
        return {"decision": "cache_scope_denied", "requested_scope": wanted}
    return cache_get(db, digest, scope=own, customer=customer, by="digest")


def quarantine_cache_coordinate(db, coordinate, *, scope="shared", customer=None,
                                reason=None):
    _ensure(db)
    if scope == "customer":
        scope = f"customer:{customer}"
    alias = _row(db, "SELECT * FROM ir_cache_aliases WHERE scope=? AND coordinate=?",
                 (scope, coordinate))
    if not alias:
        return {"decision": "cache_coordinate_missing"}
    db.execute("UPDATE ir_cache_aliases SET state='poisoned' WHERE scope=? AND coordinate=?",
               (scope, coordinate))
    db.execute("UPDATE ir_cache_entries SET quarantined=1 WHERE scope=? AND digest=?",
               (scope, alias["digest"]))
    _commit(db)
    return {"decision": "cache_quarantined", "scope": scope,
            "coordinate": coordinate, "digest": alias["digest"], "reason": reason}


def audit_shared_cache(db):
    """Rehash every shared blob, detect alias drift and customer material leaks."""
    _ensure(db)
    findings = []
    entries = _rows(db, "SELECT * FROM ir_cache_entries WHERE scope='shared'")
    known_digests = set()
    for e in entries:
        known_digests.add(e["digest"])
        if e["quarantined"]:
            findings.append({"code": "entry_quarantined", "digest": e["digest"]})
        if sha256_hex(e["blob"] or b"") != e["digest"]:
            findings.append({"code": "blob_digest_mismatch", "digest": e["digest"]})
        for leak in _scan_markers(db, e["blob"]):
            findings.append({"code": "secret_material_leak", "digest": e["digest"],
                             "marker": leak["marker"]})

    for a in _rows(db, "SELECT * FROM ir_cache_aliases WHERE scope='shared'"):
        if a["state"] == "poisoned":
            findings.append({"code": "alias_poisoned", "coordinate": a["coordinate"],
                             "digest": a["digest"]})
        elif a["digest"] not in known_digests:
            findings.append({"code": "alias_dangling", "coordinate": a["coordinate"],
                             "digest": a["digest"]})
    return {"decision": "cache_clean" if not findings else "cache_findings",
            "findings": findings}


# ---------------------------------------------------------------------------
# end-to-end chain audit + reconciliation with provisional ledger
# ---------------------------------------------------------------------------

def audit_order_chain(db, order_id, *, source_bytes=None, artifact_bytes=None, at=None):
    """Recompute source digest, verify manifest, compare download vs boot proof."""
    _ensure(db)
    o = _row(db, "SELECT * FROM ir_orders WHERE id=?", (order_id,))
    if not o:
        return {"decision": "unknown_order", "order_id": order_id}

    result = {"decision": "chain_audited", "order_id": order_id, "checks": {}}
    build = _row(db, "SELECT * FROM image_builds WHERE id=?", (o["build_id"],))
    manifest = _row(db, "SELECT * FROM ir_manifests WHERE build_id=?", (o["build_id"],))

    if build:
        result["legacy_advertised_digest"] = build["advertised_digest"]
        result["legacy_digest_is_source_digest"] = (
            build["advertised_digest"] == build["source_digest"]
        )
        if source_bytes is not None:
            result["checks"]["source_digest"] = (
                sha256_hex(source_bytes) == build["source_digest"]
            )
    if manifest:
        result["manifest_digest"] = manifest["manifest_digest"]
        result["real_image_digest"] = manifest["image_digest"]
        result["checks"]["manifest_pinned"] = True
        if source_bytes is not None:
            result["checks"]["manifest_source"] = (
                sha256_hex(source_bytes) == manifest["source_digest"]
            )
        if artifact_bytes is not None:
            result["checks"]["artifact_bytes"] = (
                sha256_hex(artifact_bytes) == manifest["image_digest"]
            )
        result["checks"]["source_is_not_image_identity"] = (
            manifest["source_digest"] != manifest["image_digest"]
        )
    else:
        result["checks"]["manifest_pinned"] = False

    download = _row(
        db,
        "SELECT * FROM ir_downloads WHERE order_id=? AND state='verified' "
        "ORDER BY at DESC, rowid DESC LIMIT 1",
        (order_id,),
    )
    result["verified_download_digest"] = download["actual_digest"] if download else None
    result["checks"]["download_verified"] = bool(download)

    measurement = latest_measurement(db, o["device_id"])
    result["latest_measurement_digest"] = (
        measurement["image_digest"] if measurement else None
    )
    result["checks"]["boot_measurement_present"] = bool(measurement)

    if download and measurement:
        result["download_runtime_consistent"] = (
            download["actual_digest"] == measurement["image_digest"]
        )
        result["checks"]["download_boot_match"] = result["download_runtime_consistent"]
    else:
        result["download_runtime_consistent"] = None

    accepted = _row(db, "SELECT * FROM ir_acceptances WHERE order_id=? AND state='accepted'",
                    (order_id,))
    result["accepted"] = bool(accepted)
    result["order_state"] = o["state"]
    return result


def audit_provisional_delivery(db, delivery_id, *, artifact_bytes=None, at=None):
    """Explain why a provisional accepted row is not real delivery evidence."""
    _ensure(db)
    d = _row(db, "SELECT * FROM image_deliveries WHERE id=?", (delivery_id,))
    if not d:
        return {"decision": "unknown_provisional_delivery", "delivery_id": delivery_id}
    b = _row(db, "SELECT * FROM image_builds WHERE id=?", (d["build_id"],))
    findings = []
    if b and b["advertised_digest"] == b["source_digest"]:
        findings.append("advertised_digest_is_source_digest")
    if d["state"] == "accepted":
        findings.append("acceptance_based_on_string_comparison_only")
    manifest = _row(db, "SELECT * FROM ir_manifests WHERE build_id=?", (d["build_id"],))
    if not manifest:
        findings.append("no_signed_build_manifest")
    if artifact_bytes is not None and b:
        if sha256_hex(artifact_bytes) != b["advertised_digest"]:
            findings.append("actual_bytes_do_not_match_advertised_digest")
    findings.append("no_device_boot_measurement")
    return {
        "decision": "provisional_acceptance_unverified",
        "delivery_id": delivery_id, "build_id": d["build_id"],
        "provisional_state": d["state"], "findings": findings,
    }


# ---------------------------------------------------------------------------
# architecture guidance — same evidence chain, different boundaries
# ---------------------------------------------------------------------------

ARCHITECTURES = {
    "common": {
        "binary_bytes": "one identical common image digest for every customer",
        "per_customer_identity": "independently signed config envelope "
                                "(customer key + tenant policy), own generation/revocation",
        "revocation_granularity": "common image digest (new installs for everyone) "
                                 "plus per-customer config generation/key",
        "shared_cache_scope": "shared partition holds common image bytes only; "
                              "keys/policies stay in customer:<id> partitions",
        "offline_verification_object": "common image digest + signed config validity/"
                                       "overlap window + signed revocation bundle",
        "installed_bytes": "identical image bytes, customer-specific config bytes",
    },
    "dedicated": {
        "binary_bytes": "per-customer signed image digest with tenant policy embedded",
        "per_customer_identity": "the release/image digest itself; optional key config "
                                 "still separately rotated",
        "revocation_granularity": "single customer image digest; other customers' "
                                  "releases untouched",
        "shared_cache_scope": "no tenant image in shared; images live in "
                              "customer:<id> partitions and cross-tenant reads are denied",
        "offline_verification_object": "the dedicated image digest measured at boot + "
                                       "device attestation + revocation bundle",
        "installed_bytes": "different image bytes per customer/policy",
    },
}


def architecture_plan(mode):
    if mode not in ARCHITECTURES:
        return {"decision": "unknown_architecture", "mode": mode,
                "supported": sorted(ARCHITECTURES)}
    return {"decision": "architecture_plan", "mode": mode, **ARCHITECTURES[mode]}


# ---------------------------------------------------------------------------
# op dispatcher (codebase run(db, command) convention)
# ---------------------------------------------------------------------------

def run(db, command):
    """Small command dispatcher.  The named functions are the primary API."""
    _ensure(db)
    op = command.get("op")
    payload = {k: v for k, v in command.items() if k != "op"}
    dispatch = {
        "register_signer": register_signer,
        "register_device": register_device,
        "pin_manifest": pin_manifest,
        "verify_manifest": verify_manifest_inputs,
        "reproduce": attest_reproduction,
        "publish_release": publish_release,
        "verify_release": verify_release,
        "issue_config": issue_config,
        "rotate_key": rotate_customer_key,
        "revoke_config": revoke_config,
        "open_order": open_order,
        "download": record_download,
        "install": attempt_install,
        "measure": record_measurement,
        "accept": accept_delivery,
        "correct_order": correct_order,
        "withdraw": withdraw_release,
        "plan_withdrawal": plan_withdrawal,
        "withdrawal_progress": withdrawal_progress,
        "bundle": create_revocation_bundle,
        "stage_evidence": stage_device_evidence,
        "cache_put": cache_put_image,
        "cache_put_customer_material": cache_put_customer_material,
        "cache_get": cache_get,
        "cache_quarantine": quarantine_cache_coordinate,
        "audit_cache": audit_shared_cache,
        "device_view": device_view,
        "customer_view": customer_view,
        "fleet_view": fleet_view,
        "chain_audit": audit_order_chain,
        "provisional_audit": audit_provisional_delivery,
        "global_latest": set_global_latest,
        "architecture": architecture_plan,
    }
    dispatch.update({
        "sign": publish_release,
        "publish": publish_release,
        "verify_package": verify_release,
        "download_package": record_download,
        "boot_proof": record_measurement,
        "measure_boot": record_measurement,
        "acceptance": accept_delivery,
        "accept": accept_delivery,
        "revoke": withdraw_release,
        "revoke_release": withdraw_release,
        "rollback_status": withdrawal_progress,
        "rotate": rotate_customer_key,
        "correct": correct_order,
        "status": fleet_view,
        "cache_audit": audit_shared_cache,
    })
    fn = dispatch.get(op)
    if fn is None:
        return {"decision": "unknown_operation", "op": op}
    if op == "architecture":
        return architecture_plan(**payload)
    return fn(db, **payload)


# Friendly aliases for callers used to release-language names.
build_manifest = pin_manifest
record_build = record_legacy_build
record = record_legacy_build
provisional = provisional_accept
sign_release = publish_release
create_release = publish_release
verify_package = verify_release
download_package = record_download
record_boot_proof = record_measurement
measure_boot = record_measurement
boot_receipt = record_measurement
accept = accept_delivery
acceptance = accept_delivery
accept_delivery_release = accept_delivery
withdraw = withdraw_release
revoke_release = withdraw_release
withdraw_release_safely = withdraw_release
revocation_plan = plan_withdrawal
fallback_status = withdrawal_progress
rotate_key = rotate_customer_key
rotate_customer_config = rotate_customer_key
correct = correct_order
correct_customer_order = correct_order
cache_put = cache_put_image
cache_get_image = cache_get
audit_cache = audit_shared_cache
customer_status = customer_view
device_status = device_view
fleet_status = fleet_view
