from flask import flash, make_response, redirect, render_template, url_for

import db
from services import live_cache, payloads, queries
from auth import security


def register_routes(app):
    @app.get("/dashboard")
    @security.login_required
    def dashboard():
        categories = queries.get_categories()
        user = queries.get_current_user()
        current_ts = db.now_ts()
        recent_sessions, recent_total = queries.recent_sessions_for_user(
            user["id"], limit=10, offset=0
        )
        trend_rows = queries.user_activity_grid(user["id"], current_ts, days=14)
        initial_data = {
            # claim_alert=False: page renders also happen for prefetches and
            # SW fetches that never run the JS - see build_status_payload.
            "status": payloads.build_status_payload(
                user["id"], current_ts, current_ts, claim_alert=False
            ),
            "digest": payloads.build_weekly_digest(user["id"], current_ts, limit=5),
            "recent": {
                "sessions": recent_sessions,
                "total": recent_total,
                "has_more": len(recent_sessions) < recent_total,
            },
            "trend": {
                "days": [row["date"] for row in trend_rows],
                "seconds": [row["seconds"] for row in trend_rows],
            },
        }
        return render_template(
            "dashboard.html",
            categories=categories,
            user=user,
            active_page="dashboard",
            initial_data=initial_data,
            # "desktop" adds a media condition to the preload: below 768px the
            # dashboard's charts sit behind a closed disclosure, so preloading
            # the bundle there would fetch exactly what we just deferred.
            preload_charts="desktop",
        )

    # The pages below embed their first data snapshot in the HTML (same
    # pattern as the dashboard's initial_data) so they render populated on
    # arrival instead of showing a "Loading…" row until a follow-up API
    # round trip completes. Every payload mirrors the corresponding /api
    # endpoint's shape exactly, so the page scripts seed with the same
    # apply/render functions they use for polling.

    @app.get("/weekly-leaderboard")
    @security.login_required
    def weekly_leaderboard():
        user = queries.get_current_user()
        current_ts = db.now_ts()
        base = live_cache.weekly_digest_base(current_ts, limit=None)
        initial_data = {
            # Seeds the mobile session dock without a round trip. claim_alert=False
            # for the same reason the dashboard uses it: page renders also happen
            # for link prefetches and service-worker navigation fetches that never
            # run the page JS, and a claim there would eat the one-shot alert.
            "status": payloads.build_status_payload(
                user["id"], current_ts, current_ts, claim_alert=False
            ),
            "leaderboard": base["leaderboard"],
            "server_ts": current_ts,
            "since_ts": base["since_ts"],
        }
        return render_template(
            "weekly_leaderboard.html",
            user=user,
            active_page="weekly_leaderboard",
            initial_data=initial_data,
            preload_charts=True,
        )

    @app.get("/all-time-stats")
    @security.login_required
    def all_time_stats():
        user = queries.get_current_user()
        current_ts = db.now_ts()
        initial_data = {
            # Seeds the mobile session dock without a round trip. claim_alert=False
            # for the same reason the dashboard uses it: page renders also happen
            # for link prefetches and service-worker navigation fetches that never
            # run the page JS, and a claim there would eat the one-shot alert.
            "status": payloads.build_status_payload(
                user["id"], current_ts, current_ts, claim_alert=False
            ),
            "leaderboard": {
                "leaderboard": live_cache.all_time_leaderboard(current_ts),
                "server_ts": current_ts,
            },
            "stats": {
                "my_categories": live_cache.user_all_time_categories(user["id"], current_ts),
                "team_categories": live_cache.team_all_time_categories(current_ts),
            },
        }
        return render_template(
            "all_time_stats.html",
            user=user,
            active_page="all_time_stats",
            initial_data=initial_data,
            preload_charts=True,
        )

    @app.get("/users/<int:user_id>")
    @security.login_required
    def user_profile(user_id: int):
        target_user = queries.get_user_by_id(user_id)
        if not target_user:
            flash("User not found.", "error")
            return redirect(url_for("dashboard"))
        current_user = queries.get_current_user()
        categories = queries.get_categories()
        current_ts = db.now_ts()
        grid_rows = queries.user_activity_grid(user_id, current_ts, days=140)
        recent_sessions, recent_total = queries.recent_sessions_for_user(
            user_id, limit=10, offset=0
        )
        initial_data = {
            # Seeds the mobile session dock without a round trip. claim_alert=False
            # for the same reason the dashboard uses it: page renders also happen
            # for link prefetches and service-worker navigation fetches that never
            # run the page JS, and a claim there would eat the one-shot alert.
            "status": payloads.build_status_payload(
                current_user["id"], current_ts, current_ts, claim_alert=False
            ),
            "stats": {
                "categories": live_cache.user_all_time_categories(user_id, current_ts),
            },
            "grid": {
                "days": [row["date"] for row in grid_rows],
                "seconds": [row["seconds"] for row in grid_rows],
                "max_seconds": max((row["seconds"] for row in grid_rows), default=0),
            },
            "recent": {
                "sessions": recent_sessions,
                "total": recent_total,
                "has_more": len(recent_sessions) < recent_total,
            },
        }
        return render_template(
            "user.html",
            user=current_user,
            target_user=target_user,
            can_delete_sessions=current_user["id"] == target_user["id"],
            categories=categories,
            active_page="user_profile",
            initial_data=initial_data,
            preload_charts=True,
        )

    @app.route("/service-worker.js")
    def service_worker():
        # Rendered as a template so the SW's cache name is the server-computed
        # static content hash (app.config["STATIC_VERSION"]): a deploy that
        # changes any asset yields a new SW, which installs with new versioned
        # asset URLs. Served uncacheable so browsers pick up the new SW on
        # their next navigation instead of after the old header expires.
        response = make_response(
            render_template(
                "service-worker.js", cache_version=app.config["STATIC_VERSION"]
            )
        )
        response.headers["Content-Type"] = "application/javascript"
        response.headers["Cache-Control"] = "no-cache"
        return response
