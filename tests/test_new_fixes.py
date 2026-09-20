"""Tests for the bug fixes, security hardening, perf work, and new features.

Covers:
  * S1  - account-scoped rate limiting (independent of source IP)
  * S3  - CSRF enforced on anonymous login/register (login-CSRF)
  * B3  - atomic session state transitions (status guards on UPDATEs)
  * P1  - SQL windowed aggregation parity vs the Python proration helper
  * F1  - SSE live stream (/api/stream)
  * F8  - admin analytics page + JSON endpoint (admin-only)
"""

import os
import re
import sqlite3
import tempfile
import time
import unittest
from unittest.mock import patch
from pathlib import Path

import app as app_module
import config
from services import queries
from utils import helpers
from auth import security


def extract_csrf(html: bytes) -> str:
    match = re.search(rb'name="csrf-token" content="([^"]*)"', html)
    if not match:
        raise AssertionError("CSRF token not found in HTML response")
    return match.group(1).decode()


class TimeStatTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test.db")
        app_module.DB_PATH = self.db_path
        self.env_patch = patch.dict(
            os.environ, {"ADMIN_CODE": "test-admin-code-12345"}
        )
        self.env_patch.start()
        self.app = app_module.create_app()
        self.app.config["TESTING"] = True
        # Writes made directly via sqlite3 in tests bypass live_cache.invalidate();
        # a zero check interval makes the cache notice them on the next read.
        self.app.config["LIVE_CACHE_CHECK_INTERVAL"] = 0
        self.client = self.app.test_client()

    def tearDown(self) -> None:
        self.env_patch.stop()
        self.temp_dir.cleanup()

    def _register(self, username: str):
        """Register and return the rendered 6-digit code + a fresh csrf token."""
        page = self.client.get("/register")
        csrf = extract_csrf(page.data)
        resp = self.client.post(
            "/register",
            data={"username": username, "csrf_token": csrf},
            follow_redirects=False,
        )
        self.assertEqual(resp.status_code, 200)
        code_match = re.search(rb"(\d{6})", resp.data)
        self.assertIsNotNone(code_match, "login code should be shown after register")
        return code_match.group(1).decode()

    def _login(self, username: str, code: str):
        page = self.client.get("/login")
        csrf = extract_csrf(page.data)
        resp = self.client.post(
            "/login",
            data={"username": username, "code": code, "csrf_token": csrf},
            follow_redirects=True,
        )
        return resp

    def _logout(self, csrf: str):
        self.client.post("/logout", data={"csrf_token": csrf}, follow_redirects=False)

    def _active_session_id(self) -> int:
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT id FROM sessions WHERE status IN ('running','paused') ORDER BY id DESC LIMIT 1"
            ).fetchone()
            self.assertIsNotNone(row)
            return int(row[0])


class AccountScopedRateLimitTests(TimeStatTestCase):
    def test_account_lockout_independent_of_ip(self):
        code = self._register("lockme")
        # We're logged in as lockme; log out to attempt logins.
        page = self.client.get("/dashboard")
        csrf = extract_csrf(page.data)
        self._logout(csrf)

        # Rotate the source IP on every call so each attempt comes from a
        # "fresh" IP. The per-IP bucket therefore never fills, and only the
        # account-scoped bucket should lock the account.
        counter = {"n": 0}

        def rotating_addr():
            counter["n"] += 1
            return f"10.0.{counter['n'] // 250}.{counter['n'] % 250}"

        with patch.object(helpers, "client_addr", side_effect=rotating_addr):
            for _ in range(config.LOGIN_ACCOUNT_MAX_ATTEMPTS):
                page = self.client.get("/login")
                csrf = extract_csrf(page.data)
                self.client.post(
                    "/login",
                    data={"username": "lockme", "code": "000000", "csrf_token": csrf},
                    follow_redirects=True,
                )
            # The next attempt from yet another fresh IP must be locked out
            # by the account-scoped bucket.
            page = self.client.get("/login")
            csrf = extract_csrf(page.data)
            resp = self.client.post(
                "/login",
                data={"username": "lockme", "code": code, "csrf_token": csrf},
                follow_redirects=True,
            )
        self.assertIn(b"Too many login attempts", resp.data)


class LoginLockoutKeyNormalizationTests(TimeStatTestCase):
    def test_whitespace_variants_share_one_attempt_budget(self):
        """Rate-limit buckets are keyed on the whitespace-collapsed username
        (what parse_username produces and the users table stores). Keying on
        the raw field let "a b", "a  b" and "a\tb" each draw a separate
        budget against the same account, multiplying the real attempt
        ceiling for any username containing a space."""
        code = self._register("multi word")
        page = self.client.get("/dashboard")
        self._logout(extract_csrf(page.data))

        variants = ["multi word", "multi  word", "multi\tword", " multi word "]
        for i in range(config.LOGIN_MAX_ATTEMPTS):
            page = self.client.get("/login")
            csrf = extract_csrf(page.data)
            self.client.post(
                "/login",
                data={
                    "username": variants[i % len(variants)],
                    "code": "000000",
                    "csrf_token": csrf,
                },
                follow_redirects=True,
            )

        # The budget is now spent regardless of which spelling is used, and
        # even the correct code is refused.
        page = self.client.get("/login")
        csrf = extract_csrf(page.data)
        resp = self.client.post(
            "/login",
            data={"username": "multi word", "code": code, "csrf_token": csrf},
            follow_redirects=True,
        )
        self.assertIn(b"Too many login attempts", resp.data)

        with sqlite3.connect(self.db_path) as conn:
            keys = [
                row[0]
                for row in conn.execute(
                    "SELECT key FROM auth_attempts WHERE scope = ?",
                    (security.LOGIN_ACCOUNT_SCOPE,),
                ).fetchall()
            ]
        self.assertEqual(len(keys), 1, f"expected one account bucket, got {keys}")


class LoginCsrfTests(TimeStatTestCase):
    def test_login_without_csrf_token_is_rejected(self):
        self._register("csrfuser")
        page = self.client.get("/dashboard")
        csrf = extract_csrf(page.data)
        self._logout(csrf)

        # Correct username + code but NO csrf_token -> must be bounced by the
        # CSRF guard, not processed by the credential check.
        resp = self.client.post(
            "/login",
            data={"username": "csrfuser", "code": "000000"},
            follow_redirects=True,
        )
        self.assertIn(b"Invalid request token", resp.data)
        with self.client.session_transaction() as sess:
            self.assertNotIn("user_id", sess)


class FrontendResilienceTests(unittest.TestCase):
    """Guard the shared-script failure path that browser tests may miss."""

    ROOT = Path(__file__).resolve().parents[1]

    def test_base_template_provides_shared_runtime_fallbacks(self):
        base = (self.ROOT / "templates" / "base.html").read_text()
        self.assertIn('window.MEDALS = ["🥇", "🥈", "🥉"];', base)
        self.assertIn("window.postJson = window.postJson ||", base)
        self.assertIn("window.renderOrUpdateChart = window.renderOrUpdateChart || (() => null);", base)
        self.assertIn("Some optional enhancements are unavailable", base)
        self.assertIn("__timestatCommonLoadFailed", base)

    def test_leaderboards_do_not_index_missing_medals_global(self):
        for name in (
            "dashboard.html",
            "weekly_leaderboard.html",
            "all_time_stats.html",
            "admin_analytics.html",
        ):
            page = (self.ROOT / "templates" / name).read_text()
            self.assertIn("Array.isArray(window.MEDALS)", page, name)
            self.assertNotIn("window.MEDALS[row.rank - 1]", page, name)

    def test_tracker_fields_are_named_on_mobile(self):
        """The session-tracker inputs must always be labelled on a phone.

        They used to be named by a shortened placeholder because
        `.tracker-section label > span` was hidden to buy vertical space, and
        reading an unset data-mobile-placeholder assigned undefined - every
        mobile user saw the literal word "undefined" in both fields. The tab
        bar freed that space, so the real labels are visible again and the
        whole swap is gone. Guard both halves: the labels must not be hidden,
        and no remnant of the swap may survive.
        """
        dashboard = (self.ROOT / "templates" / "dashboard.html").read_text()
        style = (self.ROOT / "static" / "style.css").read_text()

        for fragment in ("mobilePlaceholder", "data-mobile-placeholder"):
            self.assertNotIn(fragment, dashboard, "placeholder swap must be fully removed")
        self.assertNotIn("tracker-section label > span", style)

        for input_id in ('id="categoryId"', 'id="sessionNote"'):
            start = dashboard.index(input_id)
            tag = dashboard[dashboard.rindex("<input", 0, start) : dashboard.index(">", start) + 1]
            self.assertIn("placeholder=", tag, f"{input_id} still needs a placeholder")
            self.assertNotIn('placeholder=""', tag, input_id)

    def test_stylesheet_has_exactly_one_mobile_breakpoint(self):
        """Mobile CSS used to be spread over four overlapping blocks (two at
        640px, two at 768px, one at 767px) that defined the same components
        more than once and left a 1px seam at exactly 768px. There is now one
        mobile query, and it is the exact complement of Tailwind's `md:`."""
        style = (self.ROOT / "static" / "style.css").read_text()
        max_queries = re.findall(r"@media \(max-width: ([^)]+)\)", style)
        self.assertEqual(max_queries, ["767.98px"], "expected a single mobile breakpoint")

        common = (self.ROOT / "static" / "js" / "common.js").read_text()
        self.assertIn('window.MOBILE_QUERY = "(max-width: 767.98px)"', common)
        # No template or script may hard-code a competing breakpoint.
        for path in list((self.ROOT / "templates").glob("*.html")) + [common]:
            text = path.read_text() if isinstance(path, Path) else path
            self.assertNotIn("max-width: 767px", text)
            self.assertNotIn("max-width: 640px", text)

    def test_app_css_is_the_committed_build_output(self):
        """static/app.css is generated (npm run css) - a hand edit there is
        silently reverted on the next build, so it must stay byte-identical
        to tailwind.css + style.css."""
        root = self.ROOT / "static"
        expected = (root / "tailwind.css").read_bytes() + (root / "style.css").read_bytes()
        self.assertEqual(
            (root / "app.css").read_bytes(),
            expected,
            "static/app.css is stale or hand-edited - run `npm run css`",
        )

    def test_bottom_overlays_clear_the_tab_bar(self):
        """The install prompt, SW update notice, toast container and collab
        notifications were all pinned at `bottom-4`, so they stacked on each
        other - and the new tab bar sits in the same strip. They share one
        class that offsets by the tab bar, dock and safe-area inset."""
        base = (self.ROOT / "templates" / "base.html").read_text()
        common = (self.ROOT / "static" / "js" / "common.js").read_text()
        dashboard = (self.ROOT / "templates" / "dashboard.html").read_text()
        style = (self.ROOT / "static" / "style.css").read_text()

        for name, text in (("base.html", base), ("common.js", common), ("dashboard.html", dashboard)):
            self.assertNotIn("bottom-4", text, f"{name} still pins an overlay at a bare bottom-4")
        # Every element that is position-fixed to the bottom edge, wherever it
        # is built: both #swUpdateNotice variants and #installAppBtn in
        # base.html, the toast container in common.js, and the dashboard's
        # collaboration notifications.
        fixed_bottom = re.findall(r'"fixed [^"]*"', base + common + dashboard)
        fixed_bottom += re.findall(r"'fixed [^']*'", base + common + dashboard)
        self.assertTrue(fixed_bottom, "expected to find the fixed-position overlays")
        for cls in fixed_bottom:
            if "inset-0" in cls:
                continue  # full-screen modal backdrops, not bottom-anchored
            self.assertIn("app-bottom-float", cls, f"overlay not offset for the tab bar: {cls}")
        self.assertIn(".app-bottom-float {", style)
        self.assertIn("--app-tabbar-h", style)
        self.assertIn("env(safe-area-inset-bottom", style)
        self.assertIn("viewport-fit=cover", base)

    def test_every_icon_exists_in_the_subsetted_font(self):
        """static/fonts/material-symbols-rounded.woff2 is subsetted to just the
        ligatures this app uses, and there is no source font in the repo to
        regenerate it from. A ligature the font doesn't ship renders as its
        literal name - "account_circle" as words in the middle of the UI."""
        try:
            from fontTools.ttLib import TTFont
        except ImportError:
            self.skipTest("fontTools not installed")

        font = TTFont(self.ROOT / "static" / "fonts" / "material-symbols-rounded.woff2")
        char_of = {}
        for codepoint, glyph in font.getBestCmap().items():
            char_of.setdefault(glyph, chr(codepoint))
        available = set()
        for lookup in font["GSUB"].table.LookupList.Lookup:
            for sub in lookup.SubTable:
                sub = getattr(sub, "ExtSubTable", sub)
                for first, ligs in getattr(sub, "ligatures", {}).items():
                    for lig in ligs:
                        parts = [first] + list(lig.Component)
                        if all(part in char_of for part in parts):
                            available.add("".join(char_of[part] for part in parts))
        self.assertIn("timer", available, "font did not decode - check the extractor")

        # Known pre-existing offender, on an admin page outside this work's
        # scope: admin_dashboard.html renders "stop_circle" as literal text.
        # Subset-only, so the fix is to use a ligature the font ships.
        known_bad = {("admin_dashboard.html", "stop_circle")}
        missing = set()
        for path in sorted((self.ROOT / "templates").glob("*.html")):
            for name in re.findall(
                r'material-symbols-rounded[^>]*>\s*([a-z0-9_]+)\s*<', path.read_text()
            ):
                if name not in available:
                    missing.add((path.name, name))
        self.assertLessEqual(
            missing, known_bad, f"icons missing from the font subset: {sorted(missing - known_bad)}"
        )

    def test_history_cells_are_placed_by_semantic_class(self):
        """The mobile history card used to place cells with
        `td:nth-child(1..5)`, which is coupled to column order and count -
        and user.html omits the actions column for non-owners."""
        style = (self.ROOT / "static" / "style.css").read_text()
        self.assertNotIn(".history-table td:nth-child", style)
        for name in ("dashboard.html", "user.html"):
            text = (self.ROOT / "templates" / name).read_text()
            for cls in ("hist-cat", "hist-dur", "hist-note", "hist-when", "hist-actions"):
                self.assertIn(cls, text, f"{name} is missing .{cls}")

    def test_dashboard_bootstrap_handles_widget_failure(self):
        dashboard = (self.ROOT / "templates" / "dashboard.html").read_text()
        self.assertIn("bootstrap().catch", dashboard)
        self.assertIn('console.error("Dashboard bootstrap failed", err)', dashboard)


class AtomicTransitionTests(TimeStatTestCase):
    def test_pause_after_racing_finish_is_rejected(self):
        self._register("racer")
        page = self.client.get("/dashboard")
        csrf = extract_csrf(page.data)
        self.client.post(
            "/api/session/start",
            json={"category_name": "Other", "note": "race"},
            headers={"X-CSRF-Token": csrf},
        )
        session_id = self._active_session_id()

        # Capture the 'running' row as the handler reads it, then flip the DB
        # row to 'completed' underneath it (simulating a racing finish landing
        # in the check-then-act window between the read and the UPDATE).
        now = int(time.time())
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            stale = conn.execute("SELECT * FROM sessions WHERE id=?", (session_id,)).fetchone()
            conn.execute(
                "UPDATE sessions SET status='completed', end_ts=?, pause_started_ts=NULL WHERE id=?",
                (now, session_id),
            )
            conn.commit()

        with patch.object(queries, "get_active_session", return_value=stale):
            resp = self.client.post("/api/session/pause", headers={"X-CSRF-Token": csrf})
        self.assertEqual(resp.status_code, 409)
        # The session must remain completed (pause must NOT resurrect it).
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute("SELECT status FROM sessions WHERE id=?", (session_id,)).fetchone()
        self.assertEqual(row[0], "completed")

    def test_adjust_after_racing_finish_is_rejected(self):
        self._register("racer2")
        page = self.client.get("/dashboard")
        csrf = extract_csrf(page.data)
        self.client.post(
            "/api/session/start",
            json={"category_name": "Other", "note": "race"},
            headers={"X-CSRF-Token": csrf},
        )
        session_id = self._active_session_id()
        now = int(time.time())
        with sqlite3.connect(self.db_path) as conn:
            # Backdate start so there's plenty of elapsed time to "adjust".
            conn.execute("UPDATE sessions SET start_ts=? WHERE id=?", (now - 3600, session_id))
            conn.row_factory = sqlite3.Row
            stale = conn.execute("SELECT * FROM sessions WHERE id=?", (session_id,)).fetchone()
            conn.execute(
                "UPDATE sessions SET status='completed', end_ts=?, pause_started_ts=NULL WHERE id=?",
                (now, session_id),
            )
            conn.commit()

        with patch.object(queries, "get_active_session", return_value=stale):
            resp = self.client.post(
                "/api/session/adjust",
                json={"seconds": 60},
                headers={"X-CSRF-Token": csrf},
            )
        self.assertEqual(resp.status_code, 409)

    def test_concurrent_adjust_same_status_is_rejected(self):
        """Two adjusts racing against the same stale elapsed value must not
        both apply. Before the paused_seconds optimistic-lock fix, this
        endpoint was guarded only by `status IN (...)`, so a second adjust
        reading the same pre-first-adjust snapshot (e.g. an offline-queue
        retry racing a fresh click) would pass validation and double-apply,
        over-subtracting and corrupting the session's duration."""
        self._register("racer3")
        page = self.client.get("/dashboard")
        csrf = extract_csrf(page.data)
        self.client.post(
            "/api/session/start",
            json={"category_name": "Other", "note": "race"},
            headers={"X-CSRF-Token": csrf},
        )
        session_id = self._active_session_id()
        now = int(time.time())
        with sqlite3.connect(self.db_path) as conn:
            # Backdate start so there's plenty of elapsed time for two adjusts.
            conn.execute("UPDATE sessions SET start_ts=? WHERE id=?", (now - 3600, session_id))
            conn.commit()
            conn.row_factory = sqlite3.Row
            stale = conn.execute("SELECT * FROM sessions WHERE id=?", (session_id,)).fetchone()

        # First adjust applies for real, moving paused_seconds to 60.
        resp1 = self.client.post(
            "/api/session/adjust",
            json={"seconds": 60},
            headers={"X-CSRF-Token": csrf},
        )
        self.assertEqual(resp1.status_code, 200)

        # Second adjust races against the *stale* pre-first-adjust snapshot
        # (paused_seconds still 0) - simulating a concurrent request that
        # read state before the first adjust committed.
        with patch.object(queries, "get_active_session", return_value=stale):
            resp2 = self.client.post(
                "/api/session/adjust",
                json={"seconds": 60},
                headers={"X-CSRF-Token": csrf},
            )
        self.assertEqual(resp2.status_code, 409)

        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT paused_seconds FROM sessions WHERE id=?", (session_id,)
            ).fetchone()
        # Only the first adjust's 60s applied - not 120 from a double-apply.
        self.assertEqual(row[0], 60)


class AutoPauseAlertTests(TimeStatTestCase):
    def test_auto_pause_alert_delivered_exactly_once(self):
        """The auto-pause alert is a DB-backed atomic claim
        (auto_pause_pending_alert), not a one-shot Flask-session cookie
        flag, specifically so it survives being read from an SSE response
        (whose cookie writes don't reliably persist). Two reads right after
        the auto-pause transition (simulating a REST poll landing alongside
        an SSE tick) must show the alert exactly once between them, not
        zero times (lost) or twice (a stale re-delivery)."""
        self._register("sleepy")
        page = self.client.get("/dashboard")
        csrf = extract_csrf(page.data)
        self.client.post(
            "/api/session/start",
            json={"category_name": "Other", "note": "long haul"},
            headers={"X-CSRF-Token": csrf},
        )
        session_id = self._active_session_id()
        now = int(time.time())
        limit_seconds = config.MAX_SESSION_RUNNING_HOURS * 3600
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "UPDATE sessions SET start_ts=? WHERE id=?",
                (now - limit_seconds - 60, session_id),
            )
            conn.commit()

        # The 8h cap is enforced by the background sweep
        # (pause_overdue_running_sessions), not by the read path - drive it
        # directly, then two reads must deliver the alert exactly once.
        queries.pause_overdue_running_sessions(self.db_path)

        first = self.client.get("/api/status").get_json()
        second = self.client.get("/api/status").get_json()

        self.assertEqual(first["current_session"]["status"], "paused")
        self.assertEqual(second["current_session"]["status"], "paused")
        self.assertTrue(first["auto_paused_alert"])
        self.assertFalse(second["auto_paused_alert"])

    def test_dashboard_render_does_not_consume_the_alert(self):
        """Rendering /dashboard must not claim the one-shot auto-pause alert.

        The page embeds a status snapshot, but an HTML render is also
        triggered by link-hover prefetches (common.js) and service-worker
        navigation fetches - neither runs the page's JS, so a claim there
        would burn the alert with nobody watching. The live stream (or an
        explicit /api/status poll) delivers it instead.
        """
        self._register("prefetched")
        page = self.client.get("/dashboard")
        csrf = extract_csrf(page.data)
        self.client.post(
            "/api/session/start",
            json={"category_name": "Other", "note": "long haul"},
            headers={"X-CSRF-Token": csrf},
        )
        session_id = self._active_session_id()
        now = int(time.time())
        limit_seconds = config.MAX_SESSION_RUNNING_HOURS * 3600
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "UPDATE sessions SET start_ts=? WHERE id=?",
                (now - limit_seconds - 60, session_id),
            )
            conn.commit()
        queries.pause_overdue_running_sessions(self.db_path)

        # Two renders (e.g. a prefetch then the real navigation) of every page
        # that embeds a status payload. The dock seeding added the three
        # non-dashboard pages to this path, and each one has to pass
        # claim_alert=False or it eats the alert nobody ever sees.
        for _ in range(2):
            for path in ("/dashboard", "/weekly-leaderboard", "/all-time-stats", "/users/1"):
                self.assertEqual(self.client.get(path).status_code, 200, path)
        with sqlite3.connect(self.db_path) as conn:
            still_pending = conn.execute(
                "SELECT auto_pause_pending_alert FROM sessions WHERE id=?",
                (session_id,),
            ).fetchone()[0]
        self.assertEqual(still_pending, 1, "page render must leave the alert pending")

        # ...and every one of those pages seeds the mobile session dock with
        # the running session, so it paints without a round trip.
        for path in ("/dashboard", "/weekly-leaderboard", "/all-time-stats", "/users/1"):
            body = self.client.get(path).data.decode()
            seed = re.search(r"TIMESTAT_INITIAL_STATUS = (.*);", body)
            self.assertIsNotNone(seed, f"{path} does not seed the dock")
            self.assertIn('"category_name"', seed.group(1), path)

        # The embedded snapshot reports no alert, and the first real status
        # read still delivers it exactly once.
        self.assertTrue(self.client.get("/api/status").get_json()["auto_paused_alert"])
        self.assertFalse(self.client.get("/api/status").get_json()["auto_paused_alert"])


class WindowedAggregationParityTests(TimeStatTestCase):
    def test_weekly_leaderboard_matches_proration_helper(self):
        self._register("prorata")
        page = self.client.get("/dashboard")
        csrf = extract_csrf(page.data)
        self.client.post(
            "/api/session/start",
            json={"category_name": "Other", "note": "straddle"},
            headers={"X-CSRF-Token": csrf},
        )
        session_id = self._active_session_id()

        now = int(time.time())
        since = now - config.WEEK_SECONDS
        # A session that started before the 7-day cutoff and ended after it,
        # with some paused time, so the window proration actually bites.
        start_ts = since - 3 * 3600
        end_ts = now - 60
        paused = 600
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            conn.execute(
                "UPDATE sessions SET start_ts=?, end_ts=?, paused_seconds=?, status='completed', pause_started_ts=NULL WHERE id=?",
                (start_ts, end_ts, paused, session_id),
            )
            conn.commit()
            row = conn.execute("SELECT * FROM sessions WHERE id=?", (session_id,)).fetchone()

        expected = helpers.elapsed_seconds_in_window(row, now, since)

        resp = self.client.get("/api/leaderboard/weekly").get_json()
        total = sum(r["seconds"] for r in resp["leaderboard"])
        self.assertEqual(total, expected)


class SseStreamTests(TimeStatTestCase):
    def test_stream_pushes_status_events(self):
        self._register("streamer")
        page = self.client.get("/dashboard")
        csrf = extract_csrf(page.data)
        # Start a session so the status event must carry current_session.
        self.client.post(
            "/api/session/start",
            json={"category_name": "Other", "note": "live"},
            headers={"X-CSRF-Token": csrf},
        )
        rv = self.client.get("/api/stream", buffered=False)
        self.assertEqual(rv.status_code, 200)
        self.assertEqual(rv.mimetype, "text/event-stream")
        status_payload = None
        for chunk in rv.response:
            text = chunk.decode("utf-8", "replace")
            if text.startswith("event: status"):
                payload = text.split("data: ", 1)[1]
                import json as _json
                status_payload = _json.loads(payload)
                break
        rv.close()
        self.assertIsNotNone(status_payload, "expected at least one status event")
        self.assertIn("current_session", status_payload)
        self.assertIsNotNone(status_payload["current_session"])
        self.assertEqual(status_payload["current_session"]["status"], "running")

    def test_stream_requires_login(self):
        resp = self.client.get("/api/stream")
        # Not authenticated -> admin_required? no, login_required. /api/ -> 401
        self.assertEqual(resp.status_code, 401)


class AdminAnalyticsTests(TimeStatTestCase):
    def _admin_login(self):
        page = self.client.get("/admin/login")
        csrf = extract_csrf(page.data)
        self.client.post(
            "/admin/login",
            data={"code": "test-admin-code-12345", "csrf_token": csrf},
            follow_redirects=False,
        )

    def test_analytics_page_renders_for_admin(self):
        self._admin_login()
        resp = self.client.get("/admin/analytics")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Team Analytics", resp.data)

    def test_analytics_json_has_expected_shape(self):
        self._admin_login()
        resp = self.client.get("/admin/api/analytics")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        for key in (
            "hours_per_day",
            "hour_of_day",
            "active_users_per_day",
            "top_users_week",
            "categories_all_time",
            "categories_week",
            "server_ts",
        ):
            self.assertIn(key, data)
        self.assertEqual(len(data["hour_of_day"]), 24)

    def test_analytics_blocked_for_non_admin(self):
        # Register a normal user (is not admin) and try to hit analytics.
        self._register("normaluser")
        page = self.client.get("/dashboard")
        csrf = extract_csrf(page.data)
        # Non-admin user hitting the admin analytics page is redirected to admin login.
        resp = self.client.get("/admin/analytics", follow_redirects=False)
        self.assertEqual(resp.status_code, 302)
        self.assertIn("/admin/login", resp.headers.get("Location", ""))


class AdminSessionControlTests(TimeStatTestCase):
    def _admin_login(self):
        login_page = self.client.get("/admin/login")
        csrf = extract_csrf(login_page.data)
        self.client.post(
            "/admin/login",
            data={"code": "test-admin-code-12345", "csrf_token": csrf},
            follow_redirects=False,
        )
        dashboard = self.client.get("/admin")
        return extract_csrf(dashboard.data)

    def _start_session_for(self, username: str) -> int:
        self._register(username)
        page = self.client.get("/dashboard")
        csrf = extract_csrf(page.data)
        self.client.post(
            "/api/session/start",
            json={"category_name": "Other", "note": "work"},
            headers={"X-CSRF-Token": csrf},
        )
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT id FROM users WHERE username = ?", (username,)
            ).fetchone()
        return int(row[0])

    def test_admin_can_pause_and_finish_a_users_active_session(self):
        user_id = self._start_session_for("worker1")
        # Logging in as admin clears the previous (worker1) session cookie -
        # acting on worker1's session from here on is purely admin-side.
        admin_csrf = self._admin_login()

        pause_resp = self.client.post(
            f"/admin/api/users/{user_id}/session/pause",
            headers={"X-CSRF-Token": admin_csrf},
        )
        self.assertEqual(pause_resp.status_code, 200)
        self.assertEqual(pause_resp.get_json()["status"], "paused")
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT status FROM sessions WHERE user_id = ?", (user_id,)
            ).fetchone()
        self.assertEqual(row[0], "paused")

        # Pausing an already-paused session is rejected, not a silent no-op.
        repeat_pause = self.client.post(
            f"/admin/api/users/{user_id}/session/pause",
            headers={"X-CSRF-Token": admin_csrf},
        )
        self.assertEqual(repeat_pause.status_code, 400)

        finish_resp = self.client.post(
            f"/admin/api/users/{user_id}/session/finish",
            headers={"X-CSRF-Token": admin_csrf},
        )
        self.assertEqual(finish_resp.status_code, 200)
        self.assertEqual(finish_resp.get_json()["status"], "completed")
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT status, end_ts FROM sessions WHERE user_id = ?", (user_id,)
            ).fetchone()
        self.assertEqual(row[0], "completed")
        self.assertIsNotNone(row[1])

        # Nothing left to finish now.
        repeat_finish = self.client.post(
            f"/admin/api/users/{user_id}/session/finish",
            headers={"X-CSRF-Token": admin_csrf},
        )
        self.assertEqual(repeat_finish.status_code, 400)

    def test_admin_finish_accounts_for_time_already_paused(self):
        user_id = self._start_session_for("worker2")
        with sqlite3.connect(self.db_path) as conn:
            now = int(time.time())
            conn.execute(
                """
                UPDATE sessions SET start_ts = ?, status = 'paused', pause_started_ts = ?
                WHERE user_id = ?
                """,
                (now - 120, now - 30, user_id),
            )
            conn.commit()

        admin_csrf = self._admin_login()
        resp = self.client.post(
            f"/admin/api/users/{user_id}/session/finish",
            headers={"X-CSRF-Token": admin_csrf},
        )
        self.assertEqual(resp.status_code, 200)
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT paused_seconds FROM sessions WHERE user_id = ?", (user_id,)
            ).fetchone()
        # paused_seconds must include the time spent paused right up to the
        # finish, not just whatever it was when the session was last paused.
        self.assertGreaterEqual(row[0], 30)

    def test_session_controls_blocked_for_non_admin(self):
        user_id = self._start_session_for("worker3")
        self.assertTrue(user_id)
        # Log worker3 out before registering a second user - /register
        # redirects an already-logged-in session straight to /dashboard.
        page = self.client.get("/dashboard")
        self._logout(extract_csrf(page.data))
        # A different, non-admin user must not be able to pause/finish
        # someone else's session via these endpoints.
        self._register("bystander")
        page = self.client.get("/dashboard")
        csrf = extract_csrf(page.data)
        resp = self.client.post(
            f"/admin/api/users/{user_id}/session/pause",
            headers={"X-CSRF-Token": csrf},
        )
        # JSON endpoints answer 401 (not a redirect to the HTML login page,
        # which fetch() would follow and postJson would then choke on).
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(resp.get_json(), {"error": "Unauthorized"})
        # Page routes still redirect.
        page_resp = self.client.get("/admin")
        self.assertEqual(page_resp.status_code, 302)
        self.assertIn("/admin/login", page_resp.headers.get("Location", ""))


class DeletedUserSessionGuardTests(TimeStatTestCase):
    """login_required must reject a signed session cookie whose users row was
    deleted by an admin - otherwise every page the victim visits 500s with a
    TypeError until the cookie expires."""

    def _admin_login(self, client):
        page = client.get("/admin/login")
        csrf = extract_csrf(page.data)
        resp = client.post(
            "/admin/login",
            data={"code": "test-admin-code-12345", "csrf_token": csrf},
            follow_redirects=False,
        )
        self.assertEqual(resp.status_code, 302)
        return extract_csrf(client.get("/admin").data)

    def test_deleted_users_cookie_is_rejected_not_500(self):
        # self.client holds the victim's cookie (register auto-logs in).
        self._register("victim")
        self.assertEqual(self.client.get("/dashboard").status_code, 200)

        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT id FROM users WHERE username = 'victim'"
            ).fetchone()
        self.assertIsNotNone(row)
        victim_id = row[0]

        # A separate client acts as admin and deletes the victim's row.
        admin = self.app.test_client()
        admin_csrf = self._admin_login(admin)
        resp = admin.post(
            f"/admin/users/{victim_id}/delete",
            data={"csrf_token": admin_csrf},
            follow_redirects=False,
        )
        self.assertEqual(resp.status_code, 302)

        # The victim's cookie is now orphaned: the next request must bounce to
        # login, not crash with a 500.
        resp = self.client.get("/dashboard", follow_redirects=False)
        self.assertEqual(resp.status_code, 302)
        self.assertIn("/login", resp.headers["Location"])


if __name__ == "__main__":
    unittest.main()
