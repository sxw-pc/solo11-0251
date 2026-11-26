"""Tests for the reviewable image release chain.

Scenario under test
--------------------
Builds B1 and B2 share source bytes but differ in compiler/dependencies and
real image bytes.  Customer A downloaded B1 while its device booted B2;
customer B's offline device keeps running B1 while its key rotates.  The tests
cover identity pinning, dependency/cache pollution, secret isolation,
download/boot divergence, offline old versions, signature expiry, late
acceptance after withdrawal, fallback failure and immutable order correction,
in both the common-binary and dedicated-binary architectures.
"""

import sqlite3
import unittest

from cloudcourt import image_build, image_delivery, image_release as ir


SOURCE = b"resolver source: tenant policy evaluation 1+1"

GOOD_LIB = b"libparse-1.0.0 clean dependency bytes"
POLLUTED_LIB = b"libparse-1.0.0 substituted dependency with same coordinates"
LIB_V2 = b"libparse-1.1.0 different dependency bytes"

CC1_BYTES = b"compiler-toolchain-12.3.0-clean"
CC2_BYTES = b"compiler-toolchain-13.1.0-other"

# Real artifact bytes.  B1 handles the legacy policy correctly; B2 rejects a
# normal answer on that old policy.
B1_IMAGE = b"\x7fELF-B1 compiler12 libparse1.0 correct-on-legacy-policy"
B2_IMAGE = b"\x7fELF-B2 compiler13 libparse1.1 WRONGLY-rejects-legacy-answer"
B3_IMAGE = b"\x7fELF-B3 clean-rebuild verified fallback"
DA_IMAGE = b"\x7fELF-DA dedicated build embedding tenant-a policy"
DB_IMAGE = b"\x7fELF-DB dedicated build embedding tenant-b policy"
DAFIX_IMAGE = b"\x7fELF-DAFIX dedicated fixed build tenant-a"

ISSUER = "release-issuer.example"
ISSUER_SECRET = "hmac-secret-issuer"
CONFIG_CA = "config-ca.example"
CONFIG_SECRET = "hmac-secret-config"

KEY_A = "customer-a-key-0001-private-material"
KEY_B = "customer-b-key-0001-private-material"
POLICY_A = {"tenant": "tenant-a", "legacy_policy": "accept-normal-answer",
            "upstreams": ["resolver-a"]}
POLICY_B = {"tenant": "tenant-b", "legacy_policy": "strict-window",
            "upstreams": ["resolver-b"]}


class World:
    def __init__(self):
        self.db = sqlite3.connect(":memory:")
        ir.init_schema(self.db)
        ir.register_signer(self.db, ISSUER, ISSUER_SECRET, role="issuer")
        ir.register_signer(self.db, CONFIG_CA, CONFIG_SECRET, role="config-ca")

    def close(self):
        self.db.close()

    # -- legacy provisional ledger ----------------------------------------
    def legacy_builds(self):
        image_build.record(self.db, "B1", SOURCE, "compiler-1", "release")
        image_build.record(self.db, "B2", SOURCE, "compiler-2", "release")

    # -- pinned manifests --------------------------------------------------
    def pin_b1(self, build_id="B1", image=B1_IMAGE):
        return ir.pin_manifest(
            self.db, build_id, signer=ISSUER, at=1,
            source_bytes=SOURCE,
            dependencies=[{"name": "libparse", "version": "1.0.0", "bytes": GOOD_LIB}],
            compiler_id="gcc-12.3.0", compiler_bytes=CC1_BYTES,
            params={"recipe": "release", "opt": 2},
            image_bytes=image,
        )

    def pin_b2(self, build_id="B2", image=B2_IMAGE):
        return ir.pin_manifest(
            self.db, build_id, signer=ISSUER, at=2,
            source_bytes=SOURCE,
            dependencies=[{"name": "libparse", "version": "1.1.0", "bytes": LIB_V2}],
            compiler_id="gcc-13.1.0", compiler_bytes=CC2_BYTES,
            params={"recipe": "release", "opt": 2},
            image_bytes=image,
        )

    # -- releases ----------------------------------------------------------
    def release(self, rid, build_id, at=100, expires_at=1000, **kw):
        kw.setdefault("customers", ["customer-a", "customer-b"])
        return ir.publish_release(
            self.db, rid, build_id=build_id, signer=ISSUER,
            at=at, expires_at=expires_at, **kw
        )

    # -- devices / configs ------------------------------------------------
    def device(self, did="dev-a", customer="customer-a", secret="dev-secret-a",
               online=True, last_seen=None):
        return ir.register_device(self.db, did, customer, secret,
                                  online=online, last_seen=last_seen)

    def config(self, cid="cfg-a1", customer="customer-a", key=KEY_A,
               policy=None, at=10, expires_at=900, signer=CONFIG_CA, **kw):
        if policy is None:
            policy = POLICY_A if customer == "customer-a" else POLICY_B
        return ir.issue_config(
            self.db, cid, customer=customer, signer=signer, at=at,
            expires_at=expires_at, customer_key=key, policy=policy, **kw
        )

    def measure(self, mid, did, secret, digest, at, boot_id=None,
                config_digest=None, order_id=None):
        sig = ir.attest_measurement(
            secret, device_id=did, boot_id=boot_id or ("boot-" + mid),
            image_digest=digest, at=at, config_digest=config_digest,
        )
        return ir.record_measurement(
            self.db, mid, did, at, digest, boot_id=boot_id or ("boot-" + mid),
            config_digest=config_digest, signature=sig, order_id=order_id,
        )

    def cache(self, coordinate, blob, scope="shared", **kw):
        return ir.cache_put_image(self.db, coordinate, blob, scope=scope, **kw)

    def digest(self, blob):
        return ir.sha256_hex(blob)


# ===========================================================================
# 1. build identity: same source, different toolchains / dependencies
# ===========================================================================

class BuildIdentityTests(unittest.TestCase):
    def setUp(self):
        self.w = World()

    def tearDown(self):
        self.w.close()

    def test_same_source_different_compilers_share_legacy_digest_only(self):
        w = self.w
        w.legacy_builds()
        legacy_b1 = w.db.execute(
            "SELECT advertised_digest FROM image_builds WHERE id='B1'").fetchone()[0]
        legacy_b2 = w.db.execute(
            "SELECT advertised_digest FROM image_builds WHERE id='B2'").fetchone()[0]
        # The provisional bug, reproduced: source digest is the advertised one.
        self.assertEqual(legacy_b1, legacy_b2)
        self.assertEqual(
            "accepted",
            image_delivery.provisional(w.db, "D-SEED", "B2", "customer-a", legacy_b1),
        )

        p1 = w.pin_b1()
        p2 = w.pin_b2()
        self.assertEqual(p1["source_digest"], p2["source_digest"])
        self.assertNotEqual(p1["deps_lock_digest"], p2["deps_lock_digest"])
        self.assertNotEqual(p1["compiler_digest"], p2["compiler_digest"])
        # Real artifact identities must differ even though source is identical.
        self.assertNotEqual(p1["image_digest"], p2["image_digest"])
        self.assertNotEqual(p1["manifest_digest"], p2["manifest_digest"])
        self.assertEqual(p1["image_digest"], w.digest(B1_IMAGE))
        self.assertEqual(p2["image_digest"], w.digest(B2_IMAGE))

        audit = ir.audit_provisional_delivery(
            w.db, "D-SEED", artifact_bytes=B2_IMAGE)
        self.assertEqual(audit["decision"], "provisional_acceptance_unverified")
        self.assertIn("advertised_digest_is_source_digest", audit["findings"])
        self.assertIn("acceptance_based_on_string_comparison_only", audit["findings"])
        self.assertIn("actual_bytes_do_not_match_advertised_digest", audit["findings"])
        self.assertIn("no_device_boot_measurement", audit["findings"])

    def test_manifest_conflict_is_immutable(self):
        w = self.w
        w.pin_b1()
        changed = ir.pin_manifest(
            w.db, "B1", signer=ISSUER, source_bytes=SOURCE,
            compiler_id="gcc-12.3.0", compiler_bytes=CC1_BYTES,
            image_bytes=B2_IMAGE,  # different bytes for same build id
        )
        self.assertEqual(changed["decision"], "manifest_identity_conflict")

    def test_dependency_pollution_is_detected(self):
        w = self.w
        w.pin_b1()
        good = ir.verify_manifest_inputs(
            w.db, "B1",
            dependencies=[{"name": "libparse", "version": "1.0.0", "bytes": GOOD_LIB}],
        )
        self.assertEqual(good["decision"], "manifest_verified")
        self.assertTrue(good["checks"]["dependencies"])

        polluted = ir.verify_manifest_inputs(
            w.db, "B1",
            dependencies=[{"name": "libparse", "version": "1.0.0",
                           "bytes": POLLUTED_LIB}],
        )
        self.assertEqual(polluted["decision"], "manifest_mismatch")
        self.assertIn("dependencies", polluted["mismatches"])
        finding = polluted["dependency_findings"][0]
        self.assertEqual(finding["reason"], "dependency_digest_mismatch")

        # Real image bytes and source are re-hashed, never taken on trust.
        bad_image = ir.verify_manifest_inputs(w.db, "B1", image_bytes=B2_IMAGE)
        self.assertEqual(bad_image["decision"], "manifest_mismatch")
        self.assertIn("image_digest", bad_image["mismatches"])
        source_ok = ir.verify_manifest_inputs(w.db, "B1", source_bytes=SOURCE)
        self.assertEqual(source_ok["decision"], "manifest_verified")

    def test_logs_cannot_claim_byte_identical_reproduction(self):
        w = self.w
        pinned = w.pin_b1()

        log_only = ir.attest_reproduction(
            w.db, "R-LOG", "B1", "build-machine-7", at=200,
            claimed_image_digest=pinned["image_digest"],
            log_claims_identical=True,
        )
        self.assertEqual(log_only["decision"], "log_claim_insufficient")
        self.assertEqual(log_only["status"], "log_claim_insufficient")

        different = ir.attest_reproduction(
            w.db, "R-DIFF", "B1", "build-machine-9", at=201,
            candidate_bytes=B2_IMAGE,
        )
        self.assertEqual(different["decision"], "reproduction_differs")
        self.assertEqual(different["status"], "byte_differs")

        identical = ir.attest_reproduction(
            w.db, "R-OK", "B1", "build-machine-1", at=202,
            candidate_bytes=B1_IMAGE,
        )
        self.assertEqual(identical["decision"], "reproduction_identical")
        self.assertEqual(identical["status"], "byte_identical")

        rows = w.db.execute(
            "SELECT status FROM ir_reproductions ORDER BY rowid").fetchall()
        self.assertEqual([r[0] for r in rows],
                         ["log_claim_insufficient", "byte_differs", "byte_identical"])


# ===========================================================================
# 2. shared cache isolation: customer keys / policies never leak across
# ===========================================================================

class CacheIsolationTests(unittest.TestCase):
    def setUp(self):
        self.w = World()
        self.w.config()  # registers customer-a key/policy markers

    def tearDown(self):
        self.w.close()

    def test_customer_material_kinds_refused_in_shared_cache(self):
        w = self.w
        for kind in ("customer_key", "customer_config", "tenant_policy"):
            result = ir.cache_put_image(
                w.db, f"coord-{kind}", b"whatever-bytes",
                scope="shared", kind=kind,
            )
            self.assertEqual(result["decision"],
                             "customer_material_in_shared_cache")
        self.assertEqual(
            0,
            w.db.execute("SELECT COUNT(*) c FROM ir_cache_entries "
                         "WHERE scope='shared'").fetchone()[0],
        )

    def test_shared_bytes_containing_key_are_refused(self):
        w = self.w
        blob = b"common-binary-with-" + KEY_A.encode() + b"-embedded"
        result = w.cache("evil-coord", blob)
        self.assertEqual(result["decision"], "secret_material_in_shared_cache")
        self.assertIn("customer_key:customer-a",
                      [x["marker"] for x in result["leaks"]])

        # Clean common bytes are accepted and audit clean.
        self.assertEqual("cache_stored", w.cache("common", B1_IMAGE)["decision"])
        audit = ir.audit_shared_cache(w.db)
        self.assertEqual(audit["decision"], "cache_clean")
        self.assertEqual(audit["findings"], [])

    def test_planted_legacy_leak_and_poison_are_audited(self):
        w = self.w
        blob = b"legacy shared blob containing " + KEY_A.encode()
        digest = w.digest(blob)
        # Simulate an old cache row written before the write gate existed.
        w.db.execute(
            "INSERT INTO ir_cache_entries(scope,digest,kind,customer,blob,size,"
            "created_at,quarantined) VALUES('shared',?,'image',NULL,?,?,1,0)",
            (digest, sqlite3.Binary(blob), len(blob)),
        )
        w.db.execute(
            "INSERT INTO ir_cache_aliases(scope,coordinate,digest,state) "
            "VALUES('shared','resolver/stable',?,'clean')",
            (digest,),
        )
        audit = ir.audit_shared_cache(w.db)
        codes = {(f["code"], f.get("marker")) for f in audit["findings"]}
        self.assertIn(("secret_material_leak", "customer_key:customer-a"), codes)

        # Tamper the stored blob after pinning its digest -> corruption found.
        w.db.execute("UPDATE ir_cache_entries SET blob=? WHERE digest=?",
                     (sqlite3.Binary(blob + b"-tampered"), digest))
        audit = ir.audit_shared_cache(w.db)
        self.assertIn("blob_digest_mismatch",
                      [f["code"] for f in audit["findings"]])

    def test_customer_partitions_are_cross_tenant_denied(self):
        w = self.w
        ir.issue_config(w.db, "cfg-b", customer="customer-b", signer=CONFIG_CA,
                        at=10, expires_at=900, customer_key=KEY_B,
                        policy=POLICY_B)
        put_a = ir.cache_put_customer_material(
            w.db, "key-envelope", KEY_A.encode(), customer="customer-a")
        self.assertEqual(put_a["scope"], "customer:customer-a")

        hit = ir.cache_get(w.db, put_a["digest"], scope="customer",
                           customer="customer-a", by="digest")
        self.assertEqual(hit["decision"], "cache_hit")

        denied = ir.cache_cross_tenant_get(
            w.db, put_a["digest"], customer="customer-b",
            other_customer="customer-a",
        )
        self.assertEqual(denied["decision"], "cache_scope_denied")

        # Customer B cannot even address its own read through A's scope.
        other = ir.cache_get(w.db, put_a["digest"], scope="customer:customer-a",
                             customer="customer-b", by="digest")
        self.assertEqual(other["decision"], "cache_scope_denied")

        # Shared audit is clean: customer material never entered shared.
        self.assertEqual(ir.audit_shared_cache(w.db)["decision"], "cache_clean")


# ===========================================================================
# 3. signature validity / scope
# ===========================================================================

class SignatureTests(unittest.TestCase):
    def setUp(self):
        self.w = World()
        self.w.pin_b1()

    def tearDown(self):
        self.w.close()

    def test_expired_signature_blocks_download(self):
        w = self.w
        w.release("R-OLD", "B1", at=100, expires_at=200)
        w.device()
        w.config()
        ir.open_order(w.db, "O1", customer="customer-a", device_id="dev-a",
                      release_id="R-OLD", at=150)
        ok = ir.verify_release(w.db, "R-OLD", 199, customer="customer-a",
                              action="download")
        self.assertEqual(ok["decision"], "release_valid")
        expired = ir.verify_release(w.db, "R-OLD", 201, customer="customer-a",
                                   action="download")
        self.assertEqual(expired["decision"], "signature_expired")
        dl = ir.record_download(w.db, "DL1", "O1", 201, artifact_bytes=B1_IMAGE)
        self.assertEqual(dl["decision"], "signature_expired")

    def test_authorization_scope_is_enforced(self):
        w = self.w
        w.release("R-AONLY", "B1", customers=["customer-a"])
        w.device(did="dev-b", customer="customer-b", secret="sb")
        ir.open_order  # no-op reference to keep linters calm
        opened = ir.open_order(w.db, "OB", customer="customer-b",
                               device_id="dev-b", release_id="R-AONLY", at=110)
        # Opening is allowed to record the order, but release evaluation denies.
        self.assertEqual(opened["decision"], "order_opened")
        dl = ir.record_download(w.db, "DLB", "OB", 111, artifact_bytes=B1_IMAGE)
        self.assertEqual(dl["decision"], "outside_authorization_scope")

    def test_bad_signature_and_untrusted_signer(self):
        w = self.w
        w.release("R1", "B1")
        w.db.execute("UPDATE ir_releases SET signature=? WHERE id='R1'",
                     ("0" * 64,))
        bad = ir.verify_release(w.db, "R1", 120)
        self.assertEqual(bad["decision"], "bad_signature")

        ir.pin_manifest(w.db, "BX", signer="ghost-issuer", source_bytes=SOURCE,
                         image_bytes=B3_IMAGE)
        ghost = ir.publish_release(w.db, "RX", build_id="BX",
                                   signer="ghost-issuer", at=1, expires_at=10)
        self.assertEqual(ghost["decision"], "untrusted_signer")

    def test_expired_customer_config_blocks_acceptance(self):
        w = self.w
        w.release("R1", "B1")
        w.device()
        cfg = w.config(expires_at=200)
        ir.open_order(w.db, "O1", customer="customer-a", device_id="dev-a",
                      release_id="R1", at=100, config_id="cfg-a1")
        ir.record_download(w.db, "DL1", "O1", 101, artifact_bytes=B1_IMAGE)
        w.measure("M1", "dev-a", "dev-secret-a", w.digest(B1_IMAGE), 102,
                  config_digest=cfg["config_digest"])
        accepted = ir.accept_delivery(
            w.db, "AC1", "O1", 201, measurement_id="M1",
            approved_config_digest=cfg["config_digest"])
        self.assertEqual(accepted["decision"], "config_signature_expired")


# ===========================================================================
# 4. download vs boot divergence + full A remediation + order correction
# ===========================================================================

class CustomerADivergenceTests(unittest.TestCase):
    def setUp(self):
        self.w = World()
        w = self.w
        w.legacy_builds()
        w.pin_b1()
        w.pin_b2()
        w.release("R-B1", "B1")
        w.release("R-B2", "B2")
        w.device()
        self.cfg = w.config()
        self.cfg_digest = self.cfg["config_digest"]
        # Proper content addressed entries for both digests.
        w.cache("b1-coordinate", B1_IMAGE)
        w.cache("b2-coordinate", B2_IMAGE)
        # Provisional ledger still claims the source digest was accepted.
        src = w.db.execute(
            "SELECT source_digest FROM image_builds WHERE id='B2'").fetchone()[0]
        image_delivery.provisional(w.db, "D-A-OLD", "B2", "customer-a", src)

    def tearDown(self):
        self.w.close()

    def _open_and_download(self):
        w = self.w
        ir.open_order(w.db, "O-A", customer="customer-a", device_id="dev-a",
                      release_id="R-B1", at=100, config_id="cfg-a1",
                      original_delivery_id="D-A-OLD")
        return ir.record_download(w.db, "DL-A", "O-A", 101,
                                  artifact_bytes=B1_IMAGE)

    def test_download_b1_boot_b2_is_detected(self):
        w = self.w
        self.assertEqual("download_verified",
                         self._open_and_download()["decision"])
        w.measure("M-A-B2", "dev-a", "dev-secret-a", w.digest(B2_IMAGE), 120,
                  config_digest=self.cfg_digest)

        blocked = ir.accept_delivery(
            w.db, "AC-A-BAD", "O-A", 121, measurement_id="M-A-B2",
            approved_config_digest=self.cfg_digest)
        self.assertEqual(blocked["decision"], "measurement_digest_mismatch")

        audit = ir.audit_order_chain(w.db, "O-A", source_bytes=SOURCE,
                                     artifact_bytes=B1_IMAGE)
        self.assertFalse(audit["download_runtime_consistent"])
        self.assertEqual(audit["verified_download_digest"], w.digest(B1_IMAGE))
        self.assertEqual(audit["latest_measurement_digest"], w.digest(B2_IMAGE))
        self.assertTrue(audit["checks"]["download_boot_match"] is False)
        self.assertTrue(audit["checks"]["manifest_pinned"])
        self.assertTrue(audit["checks"]["source_digest"])
        self.assertTrue(audit["checks"]["manifest_source"])
        self.assertTrue(audit["checks"]["source_is_not_image_identity"])
        self.assertTrue(audit["legacy_digest_is_source_digest"])

        # Download alone never completes delivery.
        self.assertFalse(audit["accepted"])
        self.assertEqual(audit["order_state"], "downloaded")

    def test_polluted_coordinate_is_blocked_even_before_withdrawal(self):
        w = self.w
        self._open_and_download()
        # Shared coordinate claims the normal channel but serves B2 bytes.
        polluted = w.cache("resolver/stable", B2_IMAGE)
        self.assertEqual(polluted["digest"], w.digest(B2_IMAGE))

        attempt = ir.attempt_install(w.db, "INST-1", "O-A",
                                     "resolver/stable", 110)
        self.assertEqual(attempt["decision"], "cache_coordinate_mismatch")
        # The mismatch attempt poisons the alias for review.
        alias = w.db.execute(
            "SELECT state FROM ir_cache_aliases WHERE scope='shared' "
            "AND coordinate='resolver/stable'").fetchone()[0]
        self.assertEqual(alias, "poisoned")

    def test_full_remediation_corrects_order_and_accepts_b1(self):
        w = self.w
        self._open_and_download()
        w.measure("M-A-B2", "dev-a", "dev-secret-a", w.digest(B2_IMAGE), 120,
                  config_digest=self.cfg_digest)

        # Withdraw bad B2: B1 is a viable cached fallback and A is online.
        withdrawn = ir.withdraw_release(
            w.db, "R-B2", 130, reason="legacy-policy-regression",
            fallback_release_id="R-B1",
            windows={"customer-a": 400},
        )
        self.assertEqual(withdrawn["decision"], "release_withdrawn")
        self.assertEqual(withdrawn["affected_devices"], ["dev-a"])

        # Direct B2 installs are now fenced by digest.
        b2_install = ir.attempt_install(w.db, "INST-B2", "O-A",
                                        "b2-coordinate", 131)
        self.assertEqual(b2_install["decision"], "install_blocked_withdrawn")

        # Immutable correction; the original B1 order is preserved, not deleted.
        corrected = ir.correct_order(
            w.db, "CORR-A1", "O-A", 132, kind="download_boot_divergence",
            observed_image_digest=w.digest(B2_IMAGE),
            measurement_id="M-A-B2",
            note="device booted B2 despite verified B1 download",
            replacement_order_id="O-A2", replacement_release_id="R-B1",
            replacement_config_id="cfg-a1",
        )
        self.assertEqual(corrected["decision"], "order_corrected")
        self.assertEqual(corrected["replacement_order_id"], "O-A2")
        original = ir._row(w.db, "SELECT * FROM ir_orders WHERE id='O-A'")
        self.assertEqual(original["expected_image_digest"], w.digest(B1_IMAGE))
        self.assertEqual(original["state"], "corrected")
        self.assertTrue(ir._row(w.db, "SELECT * FROM image_deliveries WHERE id='D-A-OLD'"))
        self.assertTrue(ir._row(w.db, "SELECT * FROM ir_downloads WHERE id='DL-A'"))

        # Clean the polluted coordinate and repoint at verified B1 bytes.
        ir.quarantine_cache_coordinate(w.db, "resolver/stable")
        repointed = w.cache("resolver/stable", B1_IMAGE)
        self.assertEqual(repointed["decision"], "cache_stored")

        dl2 = ir.record_download(w.db, "DL-A2", "O-A2", 133,
                                 artifact_bytes=B1_IMAGE)
        self.assertEqual(dl2["decision"], "download_verified")
        install = ir.attempt_install(w.db, "INST-A2", "O-A2",
                                     "resolver/stable", 134)
        self.assertEqual(install["decision"], "install_verified")
        self.assertEqual(install["digest"], w.digest(B1_IMAGE))

        w.measure("M-A-B1", "dev-a", "dev-secret-a", w.digest(B1_IMAGE), 135,
                  config_digest=self.cfg_digest)
        accepted = ir.accept_delivery(
            w.db, "AC-A2", "O-A2", 136, measurement_id="M-A-B1",
            approved_config_digest=self.cfg_digest)
        self.assertEqual(accepted["decision"], "delivery_accepted")

        view = ir.customer_view(w.db, "customer-a")
        self.assertEqual(view["current_image_digest"], w.digest(B1_IMAGE))
        self.assertEqual(view["current_config_digest"], self.cfg_digest)
        self.assertTrue(view["all_devices_accepted_current"])

        progress = ir.withdrawal_progress(w.db, "R-B2", at=140)
        self.assertTrue(progress["safely_withdrawn"])
        self.assertTrue(progress["all_devices_remediated"])

    def test_common_mode_requires_approved_config_identity(self):
        w = self.w
        self._open_and_download()
        # Device measurement carries the config identity, but the customer has
        # not explicitly approved it.
        w.measure("M-NOCFG", "dev-a", "dev-secret-a", w.digest(B1_IMAGE), 115,
                  config_digest=self.cfg_digest)
        missing = ir.accept_delivery(w.db, "AC-NOCFG", "O-A", 116,
                                     measurement_id="M-NOCFG")
        self.assertEqual(missing["decision"],
                         "approved_config_identity_required")

        wrong = ir.accept_delivery(
            w.db, "AC-WRONGCFG", "O-A", 117, measurement_id="M-NOCFG",
            approved_config_digest=ir.sha256_hex(b"some-other-config"))
        self.assertIn(wrong["decision"],
                      ("measurement_config_mismatch", "unknown_config"))

    def test_order_correction_without_replacement_keeps_ledger(self):
        w = self.w
        self._open_and_download()
        before = w.db.execute("SELECT COUNT(*) FROM ir_orders").fetchone()[0]
        result = ir.correct_order(
            w.db, "CORR-NOTE", "O-A", 130, kind="record_clarification",
            note="field investigation note")
        self.assertEqual(result["decision"], "order_corrected")
        self.assertIsNone(result["replacement_order_id"])
        after = w.db.execute("SELECT COUNT(*) FROM ir_orders").fetchone()[0]
        self.assertEqual(before, after)
        corr = ir._row(w.db, "SELECT * FROM ir_corrections WHERE id='CORR-NOTE'")
        self.assertEqual(corr["kind"], "record_clarification")


# ===========================================================================
# 5. key rotation alone leaves polluted cache installable
# ===========================================================================

class RotationVsCacheTests(unittest.TestCase):
    def test_rotation_does_not_remove_bad_install_path(self):
        w = World()
        w.pin_b1()
        w.pin_b2()
        w.release("R-B1", "B1")
        w.release("R-B2", "B2")
        w.device()
        cfg1 = w.config()
        # Proper B1 fallback bytes exist; the polluted coordinate serves B2.
        w.cache("b1", B1_IMAGE)
        w.cache("resolver/stable", B2_IMAGE)

        # Rotate the customer key: new signed config generation.
        cfg2 = ir.rotate_customer_key(
            w.db, "cfg-a2", customer="customer-a", signer=CONFIG_CA, at=150,
            expires_at=900, overlap_until=300)
        self.assertEqual(cfg2["decision"], "customer_key_rotated")

        # Rotation alone neither withdraws B2 nor cleans the cache: an order
        # for the still-published B2 release can install B2 bytes.
        ir.open_order(w.db, "O-B2", customer="customer-a", device_id="dev-a",
                      release_id="R-B2", at=151, config_id="cfg-a2")
        ir.record_download(w.db, "DL-B2", "O-B2", 152, artifact_bytes=B2_IMAGE)
        install = ir.attempt_install(w.db, "I-B2", "O-B2",
                                     "resolver/stable", 153)
        self.assertEqual(install["decision"], "install_verified")
        self.assertEqual(install["digest"], w.digest(B2_IMAGE))

        # Remediation needs the withdrawal + cache quarantine, not more crypto.
        withdrawn = ir.withdraw_release(w.db, "R-B2", 160,
                                        fallback_release_id="R-B1",
                                        windows={"customer-a": 400})
        self.assertEqual(withdrawn["decision"], "release_withdrawn")
        ir.quarantine_cache_coordinate(w.db, "resolver/stable")
        again = ir.attempt_install(w.db, "I-B2-2", "O-B2",
                                   "resolver/stable", 161)
        self.assertIn(again["decision"],
                      ("cache_coordinate_poisoned", "cache_entry_quarantined",
                       "install_blocked_withdrawn"))
        w.close()


# ===========================================================================
# 6. offline customer B: old version, key rotation, withdrawal boundary,
#    late acceptance, reconnect and fallback
# ===========================================================================

class OfflineCustomerBTests(unittest.TestCase):
    def setUp(self):
        self.w = World()
        w = self.w
        w.pin_b1()
        ir.pin_manifest(w.db, "B3", signer=ISSUER, at=3, source_bytes=SOURCE,
                       dependencies=[{"name": "libparse", "version": "1.0.0",
                                     "bytes": GOOD_LIB}],
                       compiler_id="gcc-12.3.0", compiler_bytes=CC1_BYTES,
                       params={"recipe": "release", "opt": 3},
                       image_bytes=B3_IMAGE)
        w.release("R-B1", "B1", at=10)
        w.release("R-B3", "B3", at=10)
        # Expired candidate fallback.
        ir.pin_manifest(w.db, "BX", signer=ISSUER, at=4, source_bytes=SOURCE,
                       image_bytes=b"expired-fallback-image")
        w.release("R-BAD", "BX", at=100, expires_at=155)

        w.device(did="dev-b", customer="customer-b", secret="dev-secret-b",
                  online=False, last_seen=50)
        self.cfg1 = w.config(cid="cfg-b1", customer="customer-b", key=KEY_B,
                             policy=POLICY_B)
        self.cfg1_digest = self.cfg1["config_digest"]
        w.cache("b1", B1_IMAGE)
        w.cache("b3", B3_IMAGE)

        # B accepted B1 while online earlier; now it is offline.
        ir.open_order(w.db, "O-B1", customer="customer-b", device_id="dev-b",
                      release_id="R-B1", at=40, config_id="cfg-b1")
        ir.record_download(w.db, "DL-B1", "O-B1", 41, artifact_bytes=B1_IMAGE)
        w.measure("M-B1", "dev-b", "dev-secret-b", w.digest(B1_IMAGE), 50,
                  config_digest=self.cfg1_digest)
        accepted = ir.accept_delivery(
            w.db, "AC-B1", "O-B1", 51, measurement_id="M-B1",
            approved_config_digest=self.cfg1_digest)
        self.assertEqual(accepted["decision"], "delivery_accepted")
        ir.set_device_online(w.db, "dev-b", False, at=51)

    def tearDown(self):
        self.w.close()

    def test_offline_b_is_not_safely_withdrawn_and_key_rotation_bridges(self):
        w = self.w
        rotated = ir.rotate_customer_key(
            w.db, "cfg-b2", customer="customer-b", signer=CONFIG_CA, at=150,
            new_key="customer-b-key-0002", expires_at=900, overlap_until=300)
        self.assertEqual(rotated["decision"], "customer_key_rotated")
        cfg2_digest = rotated["config_digest"]

        # Old config remains usable through the committed overlap window.
        _, reason = ir.verify_config(w.db, at=200, customer="customer-b",
                                     config_digest=self.cfg1_digest)
        self.assertIsNone(reason)
        _, reason = ir.verify_config(w.db, at=301, customer="customer-b",
                                     config_digest=self.cfg1_digest)
        self.assertEqual(reason, "config_rotation_overlap_ended")
        _, reason = ir.verify_config(w.db, at=160, customer="customer-b",
                                     config_digest=cfg2_digest)
        self.assertIsNone(reason)

        view = ir.customer_view(w.db, "customer-b")
        self.assertEqual(view["devices"][0]["state"], "offline_accepted")
        self.assertEqual(view["offline_old_version_devices"], [])

        # Revoking B1 common program without a fallback is refused atomically.
        blocked = ir.withdraw_release(w.db, "R-B1", 160,
                                      windows={"customer-b": 400})
        self.assertEqual(blocked["decision"], "withdrawal_blocked_fallback")
        published = ir._row(w.db, "SELECT state FROM ir_releases WHERE id='R-B1'")
        self.assertEqual(published["state"], "published")
        self.assertIsNone(ir._row(w.db, "SELECT * FROM ir_withdrawals WHERE release_id='R-B1'"))

        # An expired fallback also blocks, and still changes nothing.
        blocked_bad = ir.withdraw_release(
            w.db, "R-B1", 160, fallback_release_id="R-BAD",
            windows={"customer-b": 400})
        self.assertEqual(blocked_bad["decision"], "withdrawal_blocked_fallback")
        codes = [i["code"] for i in blocked_bad["issues"]]
        self.assertIn("fallback_signature_expired", codes)
        self.assertEqual(published["state"], "published")

        # Missing offline revocation evidence blocks as well.
        blocked_ev = ir.withdraw_release(
            w.db, "R-B1", 160, fallback_release_id="R-B3",
            windows={"customer-b": 400})
        self.assertEqual(blocked_ev["decision"],
                         "withdrawal_blocked_offline_evidence")

        # Signed bundle + staged evidence makes the atomic boundary committable.
        bundle = ir.create_revocation_bundle(
            w.db, "BUNDLE-1", ISSUER, at=160, expires_at=500,
            release_ids=["R-B1"], fallback_release_id="R-B3")
        self.assertEqual(bundle["decision"], "revocation_bundle_created")
        staged = ir.stage_device_evidence(w.db, "dev-b", "BUNDLE-1", 160)
        self.assertEqual(staged["decision"], "evidence_staged")

        done = ir.withdraw_release(
            w.db, "R-B1", 161, reason="common-program-replacement",
            fallback_release_id="R-B3", bundle_id="BUNDLE-1",
            windows={"customer-b": 400},
            device_evidence={"dev-b": "BUNDLE-1"})
        self.assertEqual(done["decision"], "release_withdrawn")

        # Withdrawal blocks new B1 installs ...
        ir.open_order(w.db, "O-B-REINSTALL", customer="customer-b",
                      device_id="dev-b", release_id="R-B1", at=162,
                      config_id="cfg-b1")
        install = ir.attempt_install(w.db, "I-B-OLD", "O-B-REINSTALL",
                                     "b1", 163, bundle_id="BUNDLE-1")
        self.assertEqual(install["decision"], "install_blocked_withdrawn")

        # ... but B is still offline on B1: not "safely withdrawn".
        progress = ir.withdrawal_progress(w.db, "R-B1", at=170)
        self.assertFalse(progress["safely_withdrawn"])
        self.assertFalse(progress["all_devices_remediated"])
        self.assertEqual(progress["devices"][0]["state"],
                         "offline_old_version")
        view = ir.customer_view(w.db, "customer-b")
        self.assertIn("dev-b", view["offline_old_version_devices"])

    def test_late_acceptance_after_withdrawal_does_not_revive_release(self):
        w = self.w
        # A second order whose evidence is all ready before withdrawal.
        ir.open_order(w.db, "O-B-LATE", customer="customer-b",
                      device_id="dev-b", release_id="R-B1", at=110,
                      config_id="cfg-b1")
        ir.record_download(w.db, "DL-B-LATE", "O-B-LATE", 111,
                           artifact_bytes=B1_IMAGE)
        w.measure("M-B-LATE", "dev-b", "dev-secret-b", w.digest(B1_IMAGE), 112,
                  config_digest=self.cfg1_digest)

        bundle = ir.create_revocation_bundle(
            w.db, "BUNDLE-L", ISSUER, 120, 500, release_ids=["R-B1"],
            fallback_release_id="R-B3")
        ir.stage_device_evidence(w.db, "dev-b", "BUNDLE-L", 120)
        ir.withdraw_release(w.db, "R-B1", 121, fallback_release_id="R-B3",
                            bundle_id="BUNDLE-L",
                            windows={"customer-b": 400},
                            device_evidence={"dev-b": "BUNDLE-L"})

        late = ir.accept_delivery(
            w.db, "AC-LATE", "O-B-LATE", 180, measurement_id="M-B-LATE",
            approved_config_digest=self.cfg1_digest)
        self.assertEqual(late["decision"], "acceptance_blocked_withdrawn")

        # Release stays withdrawn; customer current pointer is untouched.
        state = w.db.execute("SELECT state FROM ir_releases WHERE id='R-B1'").fetchone()[0]
        self.assertEqual(state, "withdrawn")
        current = ir._row(w.db, "SELECT * FROM ir_customer_current WHERE customer='customer-b'")
        self.assertEqual(current["accepted_order_id"], "O-B1")
        rejected = ir._row(w.db, "SELECT state FROM ir_acceptances WHERE id='AC-LATE'")
        self.assertEqual(rejected["state"], "rejected")

    def test_offline_reconnect_on_old_digest_then_upgrade_completes(self):
        w = self.w
        rotated = ir.rotate_customer_key(
            w.db, "cfg-b2", customer="customer-b", signer=CONFIG_CA, at=150,
            new_key="customer-b-key-0002", expires_at=900, overlap_until=400)
        cfg2_digest = rotated["config_digest"]

        bundle = ir.create_revocation_bundle(
            w.db, "BUNDLE-R", ISSUER, 155, 500, release_ids=["R-B1"],
            fallback_release_id="R-B3")
        ir.stage_device_evidence(w.db, "dev-b", "BUNDLE-R", 155)
        ir.withdraw_release(w.db, "R-B1", 156, fallback_release_id="R-B3",
                            bundle_id="BUNDLE-R",
                            windows={"customer-b": 420},
                            device_evidence={"dev-b": "BUNDLE-R"})

        # Device reconnects but is still running B1: recorded fact only, it
        # cannot make B1 current again.
        ir.set_device_online(w.db, "dev-b", True, at=200)
        reconnect = w.measure("M-B-RECONNECT", "dev-b", "dev-secret-b",
                              w.digest(B1_IMAGE), 200,
                              config_digest=self.cfg1_digest)
        self.assertEqual(reconnect["decision"], "measurement_recorded")
        self.assertEqual(w.db.execute(
            "SELECT state FROM ir_releases WHERE id='R-B1'").fetchone()[0],
            "withdrawn")
        progress = ir.withdrawal_progress(w.db, "R-B1", at=201)
        self.assertFalse(progress["safely_withdrawn"])

        # Upgrade to verified B3 + rotated config, then real acceptance.
        ir.open_order(w.db, "O-B3", customer="customer-b", device_id="dev-b",
                      release_id="R-B3", at=202, config_id="cfg-b2",
                      replacement_for="O-B1")
        ir.record_download(w.db, "DL-B3", "O-B3", 203, artifact_bytes=B3_IMAGE)
        install = ir.attempt_install(w.db, "I-B3", "O-B3", "b3", 204)
        self.assertEqual(install["decision"], "install_verified")
        w.measure("M-B3", "dev-b", "dev-secret-b", w.digest(B3_IMAGE), 205,
                  config_digest=cfg2_digest)
        accepted = ir.accept_delivery(
            w.db, "AC-B3", "O-B3", 206, measurement_id="M-B3",
            approved_config_digest=cfg2_digest)
        self.assertEqual(accepted["decision"], "delivery_accepted")

        view = ir.customer_view(w.db, "customer-b")
        self.assertEqual(view["current_image_digest"], w.digest(B3_IMAGE))
        self.assertTrue(view["all_devices_accepted_current"])
        progress = ir.withdrawal_progress(w.db, "R-B1", at=207)
        self.assertTrue(progress["safely_withdrawn"])

    def test_strict_boundary_requires_accepted_fallback_before_revoking_b1(self):
        w = self.w
        bundle = ir.create_revocation_bundle(
            w.db, "B-STRICT", ISSUER, 160, 500, release_ids=["R-B1"],
            fallback_release_id="R-B3")
        ir.stage_device_evidence(w.db, "dev-b", "B-STRICT", 160)

        # Planning distinguishes "install block can arm" from "customer safe".
        plan = ir.plan_withdrawal(
            w.db, "R-B1", 161, fallback_release_id="R-B3",
            windows={"customer-b": 400},
            device_evidence={"dev-b": "B-STRICT"})
        self.assertEqual(plan["decision"], "withdrawal_plan")
        self.assertTrue(plan["committable"])
        self.assertFalse(plan["strict_committable"])

        # Strict ordering guard refuses: offline B has no accepted B3 yet.
        blocked = ir.withdraw_release(
            w.db, "R-B1", 161, fallback_release_id="R-B3",
            windows={"customer-b": 400}, bundle_id="B-STRICT",
            device_evidence={"dev-b": "B-STRICT"},
            require_accepted_fallback=True)
        self.assertEqual(blocked["decision"],
                         "withdrawal_blocked_unaccepted_fallback")
        self.assertEqual(
            "published",
            ir._row(w.db, "SELECT state FROM ir_releases WHERE id='R-B1'")["state"])

        # After reconnect, B accepts B3; now no device is still measured on B1
        # and the strict boundary allows the common-program revocation.
        rotated = ir.rotate_customer_key(
            w.db, "cfg-b2", customer="customer-b", signer=CONFIG_CA, at=200,
            new_key="customer-b-key-0002", expires_at=900, overlap_until=400)
        ir.set_device_online(w.db, "dev-b", True, at=201)
        ir.open_order(w.db, "O-B3S", customer="customer-b", device_id="dev-b",
                      release_id="R-B3", at=202, config_id="cfg-b2")
        ir.record_download(w.db, "DL-B3S", "O-B3S", 203, artifact_bytes=B3_IMAGE)
        ir.attempt_install(w.db, "I-B3S", "O-B3S", "b3", 204)
        w.measure("M-B3S", "dev-b", "dev-secret-b", w.digest(B3_IMAGE), 205,
                  config_digest=rotated["config_digest"])
        accepted = ir.accept_delivery(
            w.db, "AC-B3S", "O-B3S", 206, measurement_id="M-B3S",
            approved_config_digest=rotated["config_digest"])
        self.assertEqual(accepted["decision"], "delivery_accepted")

        done = ir.withdraw_release(
            w.db, "R-B1", 210, fallback_release_id="R-B3",
            windows={"customer-b": 420}, require_accepted_fallback=True)
        self.assertEqual(done["decision"], "release_withdrawn")
        self.assertEqual(done["affected_devices"], [])

    def test_fallback_must_have_real_cached_bytes(self):
        w = self.w
        # R-B3 is published and valid but remove its cache entry.
        w.db.execute("DELETE FROM ir_cache_entries WHERE digest=?",
                     (w.digest(B3_IMAGE),))
        bundle = ir.create_revocation_bundle(
            w.db, "B-X", ISSUER, 160, 500, release_ids=["R-B1"])
        ir.stage_device_evidence(w.db, "dev-b", "B-X", 160)
        blocked = ir.withdraw_release(
            w.db, "R-B1", 161, fallback_release_id="R-B3",
            windows={"customer-b": 400},
            device_evidence={"dev-b": "B-X"})
        self.assertEqual(blocked["decision"], "withdrawal_blocked_fallback")
        codes = [i["code"] for i in blocked["issues"]]
        self.assertIn("fallback_artifact_not_cached", codes)


# ===========================================================================
# 7. dedicated per-tenant binary architecture
# ===========================================================================

class DedicatedArchitectureTests(unittest.TestCase):
    def setUp(self):
        self.w = World()
        w = self.w
        for bid, image in (("DA", DA_IMAGE), ("DB", DB_IMAGE), ("DAFIX", DAFIX_IMAGE)):
            ir.pin_manifest(w.db, bid, signer=ISSUER, at=10,
                            source_bytes=SOURCE,
                            params={"tenant_embedded": bid},
                            image_bytes=image)
        w.release("R-DA", "DA", mode="dedicated", customer="customer-a",
                  tenant="tenant-a")
        w.release("R-DB", "DB", mode="dedicated", customer="customer-b",
                  tenant="tenant-b")
        w.release("R-DAFIX", "DAFIX", mode="dedicated", customer="customer-a",
                  tenant="tenant-a")
        w.device(did="da", customer="customer-a", secret="sa")
        w.device(did="db", customer="customer-b", secret="sb", online=False)
        # Tenant images only ever live in customer partitions.
        w.cache("da-coord", DA_IMAGE, scope="customer:customer-a",
                customer="customer-a", kind="image")
        w.cache("db-coord", DB_IMAGE, scope="customer:customer-b",
                customer="customer-b", kind="image")
        w.cache("dafix-coord", DAFIX_IMAGE, scope="customer:customer-a",
                customer="customer-a", kind="image")

    def tearDown(self):
        self.w.close()

    def _deliver_a(self):
        w = self.w
        ir.open_order(w.db, "ODA", customer="customer-a", device_id="da",
                      release_id="R-DA", at=100)
        ir.record_download(w.db, "DLDA", "ODA", 101, artifact_bytes=DA_IMAGE)
        ir.attempt_install(w.db, "IDA", "ODA", "da-coord", 102)
        w.measure("MDA", "da", "sa", w.digest(DA_IMAGE), 103)
        return ir.accept_delivery(w.db, "ACDA", "ODA", 104,
                                  measurement_id="MDA",
                                  approved_config_digest=None)

    def test_dedicated_digests_and_partitions_are_distinct(self):
        w = self.w
        self.assertNotEqual(w.digest(DA_IMAGE), w.digest(DB_IMAGE))
        ra = ir._row(w.db, "SELECT scope_json FROM ir_releases WHERE id='R-DA'")
        import json
        self.assertEqual(json.loads(ra["scope_json"])["customers"], ["customer-a"])

        # B cannot read A's dedicated bytes from the shared cache path.
        denied = ir.cache_get(w.db, "da-coord", scope="customer",
                              customer="customer-b")
        self.assertIn(denied["decision"],
                      ("cache_scope_denied", "cache_coordinate_missing"))

    def test_dedicated_requires_measurement_just_like_common(self):
        w = self.w
        ir.open_order(w.db, "ODA2", customer="customer-a", device_id="da",
                      release_id="R-DA", at=110)
        ir.record_download(w.db, "DLDA2", "ODA2", 111, artifact_bytes=DA_IMAGE)
        # Mode flag alone cannot complete delivery.
        accepted = ir.accept_delivery(w.db, "ACDA2", "ODA2", 112,
                                      approved_config_digest=None)
        self.assertEqual(accepted["decision"], "device_measurement_required")

    def test_dedicated_end_to_end_and_tenant_scoped_withdrawal(self):
        w = self.w
        accepted_a = self._deliver_a()
        # Dedicated images carry policy in the binary and use no config digest.
        self.assertEqual(accepted_a["decision"], "delivery_accepted")

        # B offline measures its own dedicated bytes.
        w.measure("MDB", "db", "sb", w.digest(DB_IMAGE), 120)

        # A second A order with complete evidence, deliberately left
        # unaccepted until after withdrawal (late acceptance case).
        ir.open_order(w.db, "ODA-LATE", customer="customer-a", device_id="da",
                      release_id="R-DA", at=121)
        ir.record_download(w.db, "DLDA-LATE", "ODA-LATE", 122,
                           artifact_bytes=DA_IMAGE)
        w.measure("MDA-LATE", "da", "sa", w.digest(DA_IMAGE), 123)

        # Withdraw only A's dedicated digest with A's dedicated fix fallback.
        done = ir.withdraw_release(
            w.db, "R-DA", 130, fallback_release_id="R-DAFIX",
            windows={"customer-a": 400})
        self.assertEqual(done["decision"], "release_withdrawn")
        self.assertEqual(done["affected_devices"], ["da"])

        # B's dedicated release is untouched.
        self.assertEqual(
            "published",
            ir._row(w.db, "SELECT state FROM ir_releases WHERE id='R-DB'")["state"])
        b_view = ir.customer_view(w.db, "customer-b")
        self.assertIsNone(b_view["current_release_id"])  # B has not accepted yet

        # A moves to the fixed dedicated image.
        ir.open_order(w.db, "ODAF", customer="customer-a", device_id="da",
                      release_id="R-DAFIX", at=131)
        ir.record_download(w.db, "DLDAF", "ODAF", 132, artifact_bytes=DAFIX_IMAGE)
        self.assertEqual(
            ir.attempt_install(w.db, "IDAF", "ODAF", "dafix-coord", 133)["decision"],
            "install_verified")
        w.measure("MDAF", "da", "sa", w.digest(DAFIX_IMAGE), 134)
        self.assertEqual(
            ir.accept_delivery(w.db, "ACDAF", "ODAF", 135,
                               measurement_id="MDAF")["decision"],
            "delivery_accepted")

        # A late acceptance on the withdrawn dedicated release is fenced.
        late = ir.accept_delivery(w.db, "ACDA-LATE", "ODA-LATE", 140,
                                  measurement_id="MDA-LATE")
        self.assertEqual(late["decision"], "acceptance_blocked_withdrawn")

        # A global latest pointer cannot describe both tenants' real bytes.
        ir.set_global_latest(w.db, "resolver", "R-DAFIX", 141)
        glob = ir.get_global_latest(w.db, "resolver")
        views = ir.fleet_view(w.db)
        self.assertEqual(glob["image_digest"], w.digest(DAFIX_IMAGE))
        self.assertEqual(views["customer-a"]["current_image_digest"],
                         w.digest(DAFIX_IMAGE))
        self.assertEqual(views["customer-b"]["devices"][0]["latest_image_digest"],
                         w.digest(DB_IMAGE))
        self.assertNotEqual(glob["image_digest"],
                            views["customer-b"]["devices"][0]["latest_image_digest"])

    def test_architecture_plans_state_boundary_differences(self):
        common = ir.architecture_plan("common")
        dedicated = ir.architecture_plan("dedicated")
        self.assertEqual(common["decision"], "architecture_plan")
        self.assertIn("identical common image", common["binary_bytes"])
        self.assertIn("config envelope", common["per_customer_identity"])
        self.assertIn("shared partition", common["shared_cache_scope"])
        self.assertIn("config validity", common["offline_verification_object"])
        self.assertIn("per-customer signed image", dedicated["binary_bytes"])
        self.assertIn("customer:<id>", dedicated["shared_cache_scope"])
        self.assertIn("dedicated image digest",
                      dedicated["offline_verification_object"])
        unknown = ir.architecture_plan("weird")
        self.assertEqual(unknown["decision"], "unknown_architecture")


# ===========================================================================
# 8. dispatcher / global pointer sanity
# ===========================================================================

class DispatcherTests(unittest.TestCase):
    def test_run_dispatcher_and_global_pointer(self):
        db = sqlite3.connect(":memory:")
        ir.init_schema(db)
        self.assertEqual(ir.run(db, {"op": "architecture", "mode": "common"})["mode"],
                         "common")
        reg = ir.run(db, {"op": "register_signer", "subject": "s", "secret": "k"})
        self.assertEqual(reg["decision"], "signer_registered")
        pinned = ir.run(db, {
            "op": "pin_manifest", "build_id": "B1", "signer": "s",
            "source_bytes": b"src", "image_bytes": B1_IMAGE,
        })
        self.assertEqual(pinned["decision"], "manifest_pinned")
        published = ir.run(db, {
            "op": "publish_release", "release_id": "R1", "build_id": "B1",
            "signer": "s", "at": 1, "expires_at": 100, "all_customers": True,
        })
        self.assertEqual(published["decision"], "release_published")
        latest = ir.run(db, {"op": "global_latest", "channel": "c",
                             "release_id": "R1", "at": 2})
        self.assertEqual(latest["decision"], "global_latest_set")
        db.close()


if __name__ == "__main__":
    unittest.main()
