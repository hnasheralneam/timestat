import gc
import json
import os
import re
import sqlite3
import tempfile
import time
import unittest
from unittest.mock import patch

import app as app_module
import config
from services import queries
from utils import helpers


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

    def _register_and_sign_in(self, username: str):
        register_page = self.client.get("/register")
        csrf = extract_csrf(register_page.data)
        response = self.client.post(
            "/register",
            data={"username": username, "csrf_token": csrf},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 200)
        return extract_csrf(response.data)

    def _seed_completed_session(self, user_id: int, start_ts: int, end_ts: int, category="Other"):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO sessions(
                    user_id, category_name, note, start_ts, end_ts,
                    paused_seconds, status, pause_started_ts, created_ts
                )
                VALUES(?, ?, '', ?, ?, 0, 'completed', NULL, ?)
                """,
                (user_id, category, start_ts, end_ts, start_ts),
            )
            conn.commit()

    def _user_id(self, username: str) -> int:
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT id FROM users WHERE username = ?", (username,)
            ).fetchone()
            return int(row[0])


class ElapsedSecondsInWindowTests(unittest.TestCase):
    """Unit tests for utils.helpers.elapsed_seconds_in_window (B5).

    The `sessions` table only stores an aggregate `paused_seconds` total and
    a single `pause_started_ts` for whatever pause is currently active - it
    does not persist individual past pause/resume intervals. Because of
    that, elapsed_seconds_in_window cannot compute an *exact* overlap
    between active time and an arbitrary window when the window boundary
    falls strictly inside a session's span; it prorates by wall-clock share
    instead. These tests pin down that documented, approximate behavior.
    """

    def _row(self, **kwargs):
        base = {
            "start_ts": None,
            "end_ts": None,
            "paused_seconds": 0,
            "status": "completed",
            "pause_started_ts": None,
        }
        base.update(kwargs)
        return base

    def test_window_fully_containing_session_is_exact(self):
        # since_ts before the session even starts -> no proration needed,
        # the full elapsed time counts.
        row = self._row(start_ts=1000, end_ts=1500, paused_seconds=100)
        result = helpers.elapsed_seconds_in_window(row, current_ts=2000, since_ts=500)
        self.assertEqual(result, 400)  # (1500-1000) - 100 paused

    def test_session_entirely_before_window_returns_zero(self):
        row = self._row(start_ts=1000, end_ts=1200, paused_seconds=0)
        result = helpers.elapsed_seconds_in_window(row, current_ts=2000, since_ts=1500)
        self.assertEqual(result, 0)

    def test_session_with_no_pauses_is_exact_regardless_of_boundary(self):
        # With zero paused time, wall-clock proration and true active-time
        # overlap coincide exactly, since active time == wall-clock time.
        row = self._row(start_ts=1000, end_ts=2000, paused_seconds=0)
        # Window starts halfway through the session.
        result = helpers.elapsed_seconds_in_window(row, current_ts=3000, since_ts=1500)
        self.assertEqual(result, 500)

    def test_uneven_pause_distribution_is_only_approximated(self):
        # Session spans [0, 1000) with 400s paused. Suppose (unknowably, from
        # this row alone) all 400s of pause happened in [0, 400) - i.e. the
        # true active interval is [400, 1000), 600s, entirely inside a
        # window starting at since_ts=500. The *true* overlap of active time
        # with the window would be 500s (from 500 to 1000). But since we
        # only have the aggregate paused_seconds and not per-pause
        # intervals, elapsed_seconds_in_window prorates by wall-clock share
        # of the session span instead, which is a documented approximation
        # and intentionally does NOT recover the true 500s figure here.
        row = self._row(start_ts=0, end_ts=1000, paused_seconds=400)
        result = helpers.elapsed_seconds_in_window(row, current_ts=1000, since_ts=500)

        total_elapsed = 600  # 1000 - 0 - 400 paused
        overlap_span = 1000 - 500  # 500
        total_span = 1000
        expected_proration = int(total_elapsed * (overlap_span / total_span))  # 300

        self.assertEqual(result, expected_proration)
        self.assertNotEqual(
            result,
            500,
            "proration is a documented approximation, not exact overlap",
        )

    def test_currently_paused_session_excludes_ongoing_pause_from_elapsed(self):
        row = self._row(
            start_ts=0,
            end_ts=None,
            paused_seconds=0,
            status="paused",
            pause_started_ts=800,
        )
        # Full window covering the whole session: elapsed should exclude the
        # time spent in the current, still-open pause.
        result = helpers.elapsed_seconds_in_window(row, current_ts=1000, since_ts=0)
        self.assertEqual(result, 800)


class WeeklyLeaderboardAndStatsTests(TimeStatTestCase):
    def test_weekly_leaderboard_only_counts_sessions_within_the_week(self):
        self._register_and_sign_in("weekly-user")
        user_id = self._user_id("weekly-user")
        now = int(time.time())

        # A session fully inside the last week.
        self._seed_completed_session(user_id, now - 3600, now - 1800)  # 30 min
        # A session that ended long before the last week started - must not count.
        self._seed_completed_session(
            user_id, now - config.WEEK_SECONDS * 3, now - config.WEEK_SECONDS * 3 + 60
        )

        response = self.client.get("/api/leaderboard/weekly")
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        entries = {row["username"]: row["seconds"] for row in payload["leaderboard"]}
        self.assertIn("weekly-user", entries)
        self.assertEqual(entries["weekly-user"], 1800)

        all_time = self.client.get("/api/leaderboard").get_json()
        all_time_entries = {row["username"]: row["seconds"] for row in all_time["leaderboard"]}
        # All-time total includes both sessions: 1800 + 60.
        self.assertEqual(all_time_entries["weekly-user"], 1860)

    def test_api_stats_week_fields_reflect_recent_sessions_only(self):
        self._register_and_sign_in("stats-user")
        user_id = self._user_id("stats-user")
        now = int(time.time())

        self._seed_completed_session(user_id, now - 600, now - 300, category="Research")
        self._seed_completed_session(
            user_id,
            now - config.WEEK_SECONDS * 2,
            now - config.WEEK_SECONDS * 2 + 120,
            category="Research",
        )

        response = self.client.get("/api/stats")
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()

        week_totals = {row["name"]: row["seconds"] for row in payload["my_categories_week"]}
        all_totals = {row["name"]: row["seconds"] for row in payload["my_categories"]}

        self.assertEqual(week_totals.get("Research"), 300)
        self.assertEqual(all_totals.get("Research"), 420)


class CachedAggregateParityTests(TimeStatTestCase):
    """/api/leaderboard/weekly and /api/stats serve the weekly rows from the
    shared live_cache (the same snapshot the SSE digest pushes) instead of
    recomputing per request. The cached rows must be identical to a direct
    query, and must not survive a write that changes them."""

    def test_cached_weekly_rows_match_direct_queries(self):
        self._register_and_sign_in("cache-user")
        user_id = self._user_id("cache-user")
        now = int(time.time())
        self._seed_completed_session(user_id, now - 7200, now - 3600, category="Research")
        self._seed_completed_session(user_id, now - 1800, now - 900, category="Other")

        weekly = self.client.get("/api/leaderboard/weekly").get_json()
        stats = self.client.get("/api/stats").get_json()

        with self.app.test_request_context():
            since_ts = weekly["since_ts"]
            direct_board = queries.leaderboard_rows(weekly["server_ts"], since_ts=since_ts)
            direct_mine = queries.category_rows_for_user(
                user_id, weekly["server_ts"], since_ts=since_ts
            )
            direct_team = queries.category_rows_for_user(
                None, weekly["server_ts"], since_ts=since_ts
            )

        self.assertEqual(weekly["leaderboard"], direct_board)
        self.assertEqual(stats["my_categories_week"], direct_mine)
        self.assertEqual(stats["team_categories_week"], direct_team)

    def test_cached_weekly_rows_refresh_after_a_write(self):
        csrf = self._register_and_sign_in("cache-writer")
        user_id = self._user_id("cache-writer")
        now = int(time.time())
        self._seed_completed_session(user_id, now - 3600, now - 1800, category="Research")
        with sqlite3.connect(self.db_path) as conn:
            session_id = int(
                conn.execute(
                    "SELECT id FROM sessions WHERE user_id = ?", (user_id,)
                ).fetchone()[0]
            )

        # Prime the cached snapshot.
        before = self.client.get("/api/leaderboard/weekly").get_json()
        self.assertEqual(before["leaderboard"][0]["seconds"], 1800)
        self.assertEqual(
            self.client.get("/api/stats").get_json()["my_categories_week"][0]["name"],
            "Research",
        )

        # A write through the app invalidates the snapshot, so the next read
        # must reflect it rather than replaying the primed totals.
        resp = self.client.post(
            "/api/session/delete",
            json={"session_id": session_id},
            headers={"X-CSRF-Token": csrf},
        )
        self.assertEqual(resp.status_code, 200)

        after = self.client.get("/api/leaderboard/weekly").get_json()
        self.assertEqual(after["leaderboard"], [])
        self.assertEqual(
            self.client.get("/api/stats").get_json()["my_categories_week"], []
        )


class StaticGzipCacheTests(TimeStatTestCase):
    """Versioned static assets are gzipped once per process and reused."""

    def _asset_url(self, suffix=""):
        return f"/static/app.css?v={self.app.config['STATIC_VERSION']}{suffix}"

    def test_versioned_asset_is_compressed_with_a_stable_etag(self):
        headers = {"Accept-Encoding": "gzip"}
        first = self.client.get(self._asset_url(), headers=headers)
        second = self.client.get(self._asset_url(), headers=headers)
        self.assertEqual(first.status_code, 200)
        self.assertEqual(first.headers["Content-Encoding"], "gzip")
        self.assertEqual(first.headers["ETag"], second.headers["ETag"])
        self.assertEqual(first.data, second.data)
        self.assertEqual(
            first.headers["Cache-Control"], "public, max-age=31536000, immutable"
        )

        revalidated = self.client.get(
            self._asset_url(),
            headers={"Accept-Encoding": "gzip", "If-None-Match": first.headers["ETag"]},
        )
        self.assertEqual(revalidated.status_code, 304)

    def test_unknown_version_is_served_but_never_cached(self):
        """The ?v= value is client-supplied. Caching whatever arrives would
        let anyone grow the process-wide gzip cache without bound by asking
        for one asset under endlessly many invented versions."""
        headers = {"Accept-Encoding": "gzip"}
        self.client.get(self._asset_url(), headers=headers)  # populate
        for n in range(25):
            resp = self.client.get(f"/static/app.css?v=bogus{n}", headers=headers)
            self.assertEqual(resp.status_code, 200)
            self.assertEqual(resp.headers["Content-Encoding"], "gzip")

        cache = [
            obj
            for obj in gc.get_objects()
            if isinstance(obj, dict)
            and obj
            and all(
                isinstance(k, str) and k.startswith("/static/") and isinstance(v, tuple)
                for k, v in obj.items()
            )
        ]
        self.assertTrue(cache, "expected to find the static gzip cache")
        for entry in cache:
            self.assertLessEqual(len(entry), 5, f"gzip cache grew unbounded: {list(entry)}")

    def test_unversioned_static_is_not_immutably_cached(self):
        """The icon font is fetched without ?v= (the @font-face URL resolves
        relative to the stylesheet), so it must stay revalidatable rather
        than being pinned in browser caches for a year."""
        resp = self.client.get("/static/fonts/material-symbols-rounded.woff2")
        self.assertEqual(resp.status_code, 200)
        self.assertNotIn("immutable", resp.headers["Cache-Control"])
        self.assertIn("must-revalidate", resp.headers["Cache-Control"])


class EmbeddedFirstSnapshotTests(TimeStatTestCase):
    """The pages that used to open on a pulsing "Loading…" row now embed
    their first data snapshot in the HTML (same pattern as the dashboard's
    initial_data), so they paint populated without an API round trip."""

    def _initial_data(self, html: str) -> dict:
        match = re.search(r"const initialData = (\{.*?\});\n", html, re.DOTALL)
        self.assertIsNotNone(match, "page should embed an initialData snapshot")
        return json.loads(match.group(1))

    def test_pages_embed_their_first_snapshot(self):
        self._register_and_sign_in("seeded")
        user_id = self._user_id("seeded")
        now = int(time.time())
        self._seed_completed_session(user_id, now - 3600, now - 1800, category="Research")

        weekly = self._initial_data(
            self.client.get("/weekly-leaderboard").data.decode("utf-8")
        )
        self.assertEqual(weekly["leaderboard"][0]["username"], "seeded")
        self.assertEqual(weekly["leaderboard"][0]["seconds"], 1800)
        self.assertIn("since_ts", weekly)

        all_time = self._initial_data(
            self.client.get("/all-time-stats").data.decode("utf-8")
        )
        self.assertEqual(all_time["leaderboard"]["leaderboard"][0]["seconds"], 1800)
        self.assertEqual(
            {row["name"] for row in all_time["stats"]["my_categories"]}, {"Research"}
        )
        self.assertTrue(all_time["stats"]["team_categories"])

        profile = self._initial_data(
            self.client.get(f"/users/{user_id}").data.decode("utf-8")
        )
        self.assertEqual(
            {row["name"] for row in profile["stats"]["categories"]}, {"Research"}
        )
        self.assertEqual(len(profile["grid"]["days"]), len(profile["grid"]["seconds"]))
        self.assertEqual(profile["grid"]["max_seconds"], 1800)
        self.assertEqual(profile["recent"]["total"], 1)
        self.assertFalse(profile["recent"]["has_more"])

    def test_embedded_snapshots_match_their_api_equivalents(self):
        self._register_and_sign_in("parity")
        user_id = self._user_id("parity")
        now = int(time.time())
        self._seed_completed_session(user_id, now - 7200, now - 5400, category="Other")

        weekly_page = self._initial_data(
            self.client.get("/weekly-leaderboard").data.decode("utf-8")
        )
        weekly_api = self.client.get("/api/leaderboard/weekly").get_json()
        self.assertEqual(weekly_page["leaderboard"], weekly_api["leaderboard"])

        all_time_page = self._initial_data(
            self.client.get("/all-time-stats").data.decode("utf-8")
        )
        self.assertEqual(
            all_time_page["leaderboard"]["leaderboard"],
            self.client.get("/api/leaderboard").get_json()["leaderboard"],
        )
        stats_api = self.client.get("/api/stats").get_json()
        self.assertEqual(
            all_time_page["stats"]["my_categories"], stats_api["my_categories"]
        )
        self.assertEqual(
            all_time_page["stats"]["team_categories"], stats_api["team_categories"]
        )

        profile_page = self._initial_data(
            self.client.get(f"/users/{user_id}").data.decode("utf-8")
        )
        self.assertEqual(
            profile_page["stats"]["categories"],
            self.client.get(f"/api/users/{user_id}/stats").get_json()["categories"],
        )
        grid_api = self.client.get(
            f"/api/users/{user_id}/activity-grid?days=140"
        ).get_json()
        self.assertEqual(profile_page["grid"]["days"], grid_api["days"])
        self.assertEqual(profile_page["grid"]["seconds"], grid_api["seconds"])
        self.assertEqual(profile_page["grid"]["max_seconds"], grid_api["max_seconds"])
        recent_api = self.client.get(
            f"/api/users/{user_id}/recent-sessions?limit=10&offset=0"
        ).get_json()
        self.assertEqual(profile_page["recent"]["sessions"], recent_api["sessions"])
        self.assertEqual(profile_page["recent"]["total"], recent_api["total"])


class ConcurrentSessionGuardTests(TimeStatTestCase):
    def test_db_unique_index_rejects_second_active_session_row(self):
        # Directly exercises the schema-level guard added in db.py
        # (idx_sessions_one_active_per_user) independent of the app's
        # check-then-insert application logic.
        self._register_and_sign_in("dupe-user")
        with sqlite3.connect(self.db_path) as conn:
            user_id = conn.execute(
                "SELECT id FROM users WHERE username = ?", ("dupe-user",)
            ).fetchone()[0]
            conn.execute(
                """
                INSERT INTO sessions(
                    user_id, category_name, note, start_ts, status, created_ts
                )
                VALUES(?, 'Other', '', 1000, 'running', 1000)
                """,
                (user_id,),
            )
            conn.commit()
            with self.assertRaises(sqlite3.IntegrityError):
                conn.execute(
                    """
                    INSERT INTO sessions(
                        user_id, category_name, note, start_ts, status, created_ts
                    )
                    VALUES(?, 'Other', '', 2000, 'running', 2000)
                    """,
                    (user_id,),
                )

    def test_racing_start_requests_second_call_gets_clean_409_not_500(self):
        csrf = self._register_and_sign_in("racer")

        # Simulate the race window between the app's check
        # (queries.get_active_session) and its insert: force the check to
        # report "no active session" every time, as if two requests read
        # concurrently before either had committed.
        with patch.object(queries, "get_active_session", return_value=None):
            first = self.client.post(
                "/api/session/start",
                json={"category_name": "Other", "note": "first"},
                headers={"X-CSRF-Token": csrf},
            )
            second = self.client.post(
                "/api/session/start",
                json={"category_name": "Other", "note": "second"},
                headers={"X-CSRF-Token": csrf},
            )

        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 409)
        self.assertEqual(second.get_json()["error"], "session already active")

        with sqlite3.connect(self.db_path) as conn:
            active_count = conn.execute(
                "SELECT COUNT(*) FROM sessions WHERE status IN ('running', 'paused')"
            ).fetchone()[0]
        self.assertEqual(active_count, 1)

    def test_racing_resume_requests_second_call_gets_clean_409_not_500(self):
        # By construction, the unique index means a bare UPDATE can only
        # violate it in truly pathological cases, but the route still wraps
        # the write in the same try/except as start/pause for defense in
        # depth. Exercise that handling directly by making the specific
        # UPDATE statement raise IntegrityError, as sqlite3 would if two
        # workers raced to resume/activate a session for the same user at
        # once, and confirm the route degrades to a clean 409 instead of an
        # unhandled 500.
        csrf = self._register_and_sign_in("resumer")
        self.client.post(
            "/api/session/start",
            json={"category_name": "Other", "note": "x"},
            headers={"X-CSRF-Token": csrf},
        )
        self.client.post("/api/session/pause", headers={"X-CSRF-Token": csrf})

        import db as db_module

        real_get_db = db_module.get_db

        class RaceyConn:
            """Wraps the real per-request connection, forcing the specific
            resume UPDATE to fail as if a concurrent writer already won the
            race, while leaving every other query untouched."""

            def __init__(self, real_conn):
                self._conn = real_conn

            def __getattr__(self, name):
                return getattr(self._conn, name)

            def execute(self, sql, *args, **kwargs):
                if "SET status = 'running'" in sql:
                    raise sqlite3.IntegrityError(
                        "UNIQUE constraint failed: sessions.user_id"
                    )
                return self._conn.execute(sql, *args, **kwargs)

        def patched_get_db():
            return RaceyConn(real_get_db())

        with patch.object(db_module, "get_db", side_effect=patched_get_db):
            resume_resp = self.client.post(
                "/api/session/resume", headers={"X-CSRF-Token": csrf}
            )

        self.assertEqual(resume_resp.status_code, 409)
        self.assertEqual(resume_resp.get_json()["error"], "session already active")

        # And the resume endpoint still works normally afterwards, for the
        # legitimate, non-racing case.
        resume_resp_ok = self.client.post(
            "/api/session/resume", headers={"X-CSRF-Token": csrf}
        )
        self.assertEqual(resume_resp_ok.status_code, 200)


class SecretKeyStartupTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.original_base_dir = app_module.BASE_DIR
        self.original_db_path = app_module.DB_PATH
        app_module.BASE_DIR = self.temp_dir.name
        app_module.DB_PATH = os.path.join(self.temp_dir.name, "test.db")

    def tearDown(self) -> None:
        app_module.BASE_DIR = self.original_base_dir
        app_module.DB_PATH = self.original_db_path

    def test_create_app_raises_without_secret_key_outside_debug_mode(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("SECRET_KEY", None)
            os.environ.pop("FLASK_DEBUG", None)
            with self.assertRaises(RuntimeError):
                app_module.create_app()

    def test_create_app_falls_back_with_random_key_in_debug_mode(self):
        with patch.dict(os.environ, {"FLASK_DEBUG": "1"}, clear=False):
            os.environ.pop("SECRET_KEY", None)
            app = app_module.create_app()
            self.assertTrue(app.secret_key)

    def test_create_app_succeeds_when_secret_key_is_set(self):
        with patch.dict(os.environ, {"SECRET_KEY": "a-fixed-test-secret"}, clear=False):
            os.environ.pop("FLASK_DEBUG", None)
            app = app_module.create_app()
            self.assertEqual(app.secret_key, "a-fixed-test-secret")


if __name__ == "__main__":
    unittest.main()
