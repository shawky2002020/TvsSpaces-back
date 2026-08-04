# TVS Spaces API Contract

All routes are prefixed with `/api`. Dates use `yyyy-MM-dd`. Booking hours are whole hours in the configured business timezone (`Africa/Cairo` by default).

## Common error format

```json
{
  "message": "Human-readable error"
}
```

Validation errors additionally return:

```json
{
  "message": "Request validation failed",
  "fields": {
    "email": "Invalid email format"
  }
}
```

Typical statuses: `400` validation, `401` unauthenticated/invalid refresh, `403` ownership failure, `409` availability/state conflict.

---

## Authentication

### `POST /api/auth/signup` — Public

```json
{
  "username": "John Doe",
  "email": "john@example.com",
  "password": "Password123",
  "type": "freelancer"
}
```

Supported types: `student`, `freelancer`, `entrepreneur`, `remote-worker`, `startup`, `other`.

Response: `201 Created`. Sets an HttpOnly refresh cookie.

```json
{
  "token": "access-jwt",
  "user": {
    "id": 1,
    "username": "John Doe",
    "email": "john@example.com",
    "type": "freelancer",
    "role": "ROLE_USER",
    "creationDate": "2026-08-04T10:00:00.000+00:00",
    "lastLogin": "2026-08-04T10:00:00.000+00:00"
  }
}
```

Passwords and hashes are never returned.

### `POST /api/auth/login` — Public

```json
{
  "email": "john@example.com",
  "password": "Password123"
}
```

Response: `200 OK`. Sets/rotates the HttpOnly refresh cookie and returns the same safe user shape plus `message`.

### `POST /api/auth/refresh` — Public, refresh cookie required

Validates the persisted hashed refresh session, rotates the refresh token, resets the cookie, and returns:

```json
{
  "token": "new-access-jwt"
}
```

### `POST /api/auth/logout` — Public, cookie optional

Deletes the matching persisted refresh session when identifiable and always expires the cookie.

```json
{
  "message": "Logged out successfully"
}
```

---

## Profile

### `PATCH /api/user/edit` — Bearer access token required

All fields are optional. `currentPassword` is required only when changing the password.

```json
{
  "username": "Updated Name",
  "email": "updated@example.com",
  "type": "entrepreneur",
  "currentPassword": "Password123",
  "password": "NewPassword123"
}
```

Response:

```json
{
  "message": "User updated successfully",
  "user": {
    "id": 1,
    "username": "Updated Name",
    "email": "updated@example.com",
    "type": "entrepreneur",
    "role": "ROLE_USER",
    "creationDate": "2026-08-04T10:00:00.000+00:00",
    "lastLogin": "2026-08-04T10:05:00.000+00:00"
  }
}
```

The JWT subject is the immutable user ID, so email changes do not invalidate access-token identity.

---

## Public workspace catalog

### `GET /api/bookings/spaces` — Public

Returns active catalog records in the Angular-compatible shape:

```json
[
  {
    "id": "1",
    "type": "desk",
    "name": "Shared Desk",
    "slug": "shared-desk",
    "description": "Flexible seating in our open workspace areas.",
    "imageUrl": "assets/imgs/spaces/shared2.jpg",
    "additionalImages": ["assets/imgs/spaces/shared0.jpg"],
    "amenities": [
      { "name": "High-speed Wi-Fi", "icon": "wifi" }
    ],
    "pricing": {
      "hourly": 40,
      "halfDay": 35,
      "day": 32
    },
    "capacity": 7
  }
]
```

### `GET /api/bookings/spaces/{id}` — Public

Returns one workspace using the same response shape.

### `GET /api/bookings/spaces/slug/{slug}` — Public

Returns one workspace by its public route slug.

---

## Availability and pricing

All routes below require a Bearer access token.

### `GET /api/bookings/{spaceId}/availability/{date}`

Returns one-hour slots from 09:00 through 18:00:

```json
{
  "date": "2026-08-10",
  "slots": [
    { "hour": 9, "available": true },
    { "hour": 10, "available": false }
  ]
}
```

### `GET /api/bookings/{spaceId}/unavailable-dates/{year}/{month}`

```json
{
  "dates": ["2026-08-10"]
}
```

### `POST /api/bookings/availability`

```json
{
  "spaceId": "1",
  "plan": "Hourly",
  "date": "2026-08-10",
  "endDate": "2026-08-10",
  "startTime": 9,
  "endTime": 11,
  "requestedUnits": 1
}
```

Response:

```json
{
  "available": true
}
```

`plan` is optional only for backward compatibility; new clients must send it.

### `POST /api/bookings/calculate-price`

```json
{
  "spaceId": "1",
  "plan": "Hourly",
  "date": "2026-08-10",
  "endDate": "2026-08-10",
  "startTime": 9,
  "endTime": 11,
  "quantity": 1
}
```

```json
{
  "price": 80
}
```

The server ignores client-displayed totals and recalculates price during final creation.

Supported plans in the current Angular flow: `Hourly`, `Daily`. The backend also recognizes `Half-day` and `Monthly`, but they are not exposed until their UI rules are finalized.

---

## Bookings

### `POST /api/bookings` — Bearer access token required

```json
{
  "spaceId": "1",
  "plan": "Hourly",
  "date": "2026-08-10",
  "endDate": "2026-08-10",
  "startTime": 9,
  "endTime": 11,
  "quantity": 1,
  "paymentMethod": "PAY_AT_VENUE"
}
```

The only currently supported payment method is `PAY_AT_VENUE`. A successful booking is `CONFIRMED` with payment status `PENDING`.

Response: `201 Created`.

```json
{
  "id": 101,
  "reference": "BK-A5B2F9C0",
  "spaceId": "1",
  "spaceName": "Shared Desk",
  "plan": "Hourly",
  "startAt": "2026-08-10T06:00:00.000+00:00",
  "endAt": "2026-08-10T08:00:00.000+00:00",
  "reservedUnits": 1,
  "unitPrice": 80,
  "totalPrice": 80,
  "status": "CONFIRMED",
  "paymentMethod": "PAY_AT_VENUE",
  "paymentStatus": "PENDING",
  "createdAt": "2026-08-04T10:00:00.000+00:00"
}
```

Creation locks the selected space row, rechecks overlapping capacity, recalculates price, and writes the booking in one transaction.

### `GET /api/bookings/me` — Bearer access token required

Returns only bookings owned by the authenticated user.

### `PATCH /api/bookings/{id}/cancel` — Bearer access token required

Only the owner can cancel. Started, completed, or already invalid bookings cannot be newly cancelled.

```json
{
  "message": "Booking cancelled successfully"
}
```

---

## Dashboard

### `GET /api/dashboard/stats` — Bearer access token required

```json
{
  "totalReservations": 4,
  "upcomingReservations": 1,
  "activeReservations": 1,
  "completedReservations": 1,
  "cancelledReservations": 1,
  "totalVisits": 1
}
```

`totalVisits` represents completed confirmed reservations; no undefined points system is returned.
