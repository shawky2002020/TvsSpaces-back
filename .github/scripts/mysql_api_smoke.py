#!/usr/bin/env python3
"""Production-like MySQL API smoke test for TVS Spaces.

Runs in two modes:
- initial: creates a user and booking, verifies APIs, cancels, logs out, and writes state.
- persistence: after a backend restart, logs in and verifies the persisted booking/user.
"""

from __future__ import annotations

import argparse
import http.cookiejar
import json
import sys
import time
import urllib.error
import urllib.request
from datetime import date, timedelta
from pathlib import Path
from typing import Any

BASE_URL = "http://127.0.0.1:8080/api"
STATE_PATH = Path("smoke_state.json")


class ApiClient:
    def __init__(self) -> None:
        self.cookies = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.cookies)
        )
        self.access_token: str | None = None

    def request(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
        *,
        authenticated: bool = False,
        expected_status: int | tuple[int, ...] = 200,
    ) -> Any:
        body = None
        headers = {"Accept": "application/json"}
        if payload is not None:
            body = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        if authenticated:
            if not self.access_token:
                raise AssertionError(f"No access token available for {method} {path}")
            headers["Authorization"] = f"Bearer {self.access_token}"

        request = urllib.request.Request(
            f"{BASE_URL}{path}", data=body, headers=headers, method=method
        )
        allowed_statuses = (
            (expected_status,) if isinstance(expected_status, int) else expected_status
        )

        try:
            with self.opener.open(request, timeout=15) as response:
                raw = response.read().decode("utf-8")
                if response.status not in allowed_statuses:
                    raise AssertionError(
                        f"Unexpected {response.status} for {method} {path}: {raw}"
                    )
                return json.loads(raw) if raw else None
        except urllib.error.HTTPError as error:
            raw = error.read().decode("utf-8")
            if error.code in allowed_statuses:
                return json.loads(raw) if raw else None
            raise AssertionError(
                f"HTTP {error.code} for {method} {path}: {raw}"
            ) from error


def assert_safe_user(user: dict[str, Any], expected_name: str) -> None:
    assert user["username"] == expected_name, user
    assert "password" not in user, user
    assert user["email"], user
    assert user["id"], user


def initial_flow() -> None:
    client = ApiClient()
    unique = int(time.time())
    email = f"ci-smoke-{unique}@example.com"
    password = "SmokePass123"
    username = "CI Smoke User"

    signup = client.request(
        "POST",
        "/auth/signup",
        {
            "username": username,
            "email": email,
            "password": password,
            "type": "freelancer",
        },
        expected_status=201,
    )
    assert_safe_user(signup["user"], username)
    client.access_token = signup["token"]
    assert any(cookie.name == "refresh_token" for cookie in client.cookies)

    # A refresh rotates the persisted refresh session and returns a new access token.
    refreshed = client.request("POST", "/auth/refresh", {})
    assert refreshed["token"] != client.access_token
    client.access_token = refreshed["token"]

    spaces = client.request("GET", "/bookings/spaces")
    assert spaces, "Seeded spaces were not returned"
    space = next((candidate for candidate in spaces if candidate["id"] == "1"), spaces[0])
    assert space["pricing"]["hourly"] > 0
    assert isinstance(space["amenities"], list)

    by_slug = client.request("GET", f"/bookings/spaces/slug/{space['slug']}")
    assert by_slug["id"] == space["id"]

    booking_date = (date.today() + timedelta(days=7)).isoformat()
    booking_payload = {
        "spaceId": space["id"],
        "plan": "Hourly",
        "date": booking_date,
        "endDate": booking_date,
        "startTime": 9,
        "endTime": 10,
        "quantity": 1,
    }

    availability = client.request(
        "POST",
        "/bookings/availability",
        {**booking_payload, "requestedUnits": 1},
        authenticated=True,
    )
    assert availability["available"] is True, availability

    quote = client.request(
        "POST",
        "/bookings/calculate-price",
        booking_payload,
        authenticated=True,
    )
    assert quote["price"] > 0, quote

    booking = client.request(
        "POST",
        "/bookings",
        {**booking_payload, "paymentMethod": "PAY_AT_VENUE"},
        authenticated=True,
        expected_status=201,
    )
    assert booking["status"] == "CONFIRMED", booking
    assert booking["paymentStatus"] == "PENDING", booking
    assert booking["paymentMethod"] == "PAY_AT_VENUE", booking
    assert booking["totalPrice"] == quote["price"], (booking, quote)

    bookings = client.request("GET", "/bookings/me", authenticated=True)
    assert any(item["reference"] == booking["reference"] for item in bookings)

    stats = client.request("GET", "/dashboard/stats", authenticated=True)
    assert stats["totalReservations"] >= 1, stats
    assert stats["upcomingReservations"] >= 1, stats

    cancelled = client.request(
        "PATCH",
        f"/bookings/{booking['id']}/cancel",
        {},
        authenticated=True,
    )
    assert cancelled["message"] == "Booking cancelled successfully"

    post_cancel = client.request("GET", "/bookings/me", authenticated=True)
    persisted = next(
        item for item in post_cancel if item["reference"] == booking["reference"]
    )
    assert persisted["status"] == "CANCELLED", persisted

    client.request("POST", "/auth/logout", {})
    client.request("POST", "/auth/refresh", {}, expected_status=401)

    STATE_PATH.write_text(
        json.dumps(
            {
                "email": email,
                "password": password,
                "username": username,
                "reference": booking["reference"],
            }
        ),
        encoding="utf-8",
    )
    print("Initial MySQL API smoke flow passed")


def persistence_flow() -> None:
    if not STATE_PATH.exists():
        raise AssertionError("Initial smoke state is missing")

    state = json.loads(STATE_PATH.read_text(encoding="utf-8"))
    client = ApiClient()
    login = client.request(
        "POST",
        "/auth/login",
        {"email": state["email"], "password": state["password"]},
    )
    assert_safe_user(login["user"], state["username"])
    client.access_token = login["token"]

    bookings = client.request("GET", "/bookings/me", authenticated=True)
    persisted = next(
        (item for item in bookings if item["reference"] == state["reference"]),
        None,
    )
    assert persisted is not None, bookings
    assert persisted["status"] == "CANCELLED", persisted

    stats = client.request("GET", "/dashboard/stats", authenticated=True)
    assert stats["totalReservations"] >= 1, stats
    assert stats["cancelledReservations"] >= 1, stats

    client.request("POST", "/auth/logout", {})
    STATE_PATH.unlink(missing_ok=True)
    print("MySQL restart persistence smoke flow passed")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("initial", "persistence"))
    args = parser.parse_args()

    if args.mode == "initial":
        initial_flow()
    else:
        persistence_flow()
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exception:  # CI must print actionable evidence.
        print(f"Smoke test failed: {exception}", file=sys.stderr)
        raise
