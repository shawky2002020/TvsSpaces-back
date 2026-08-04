# TVS Spaces API Contract

All endpoints are prefixed with `/api`.

## 1. Authentication Endpoints

### POST /api/auth/signup
*   **Auth**: Public
*   **Request Body**:
    ```json
    {
      "username": "John Doe",
      "email": "john@example.com",
      "password": "Password123",
      "type": "Individual"
    }
    ```
*   **Response (200 OK)**:
    ```json
    {
      "token": "access_token_jwt",
      "user": {
        "id": 1,
        "username": "John Doe",
        "email": "john@example.com",
        "type": "Individual",
        "role": "ROLE_USER"
      }
    }
    ```

### POST /api/auth/login
*   **Auth**: Public
*   **Request Body**:
    ```json
    {
      "email": "john@example.com",
      "password": "Password123"
    }
    ```
*   **Response (200 OK)**:
    ```json
    {
      "message": "Login successful",
      "token": "access_token_jwt",
      "user": {
        "id": 1,
        "username": "John Doe",
        "email": "john@example.com",
        "type": "Individual",
        "role": "ROLE_USER"
      }
    }
    ```
    *   *Sets Cookie*: `refresh_token` (HttpOnly, SameSite=Strict, Secure, Max-Age=7 days)

### POST /api/auth/refresh
*   **Auth**: Public (Requires valid `refresh_token` in cookie)
*   **Response (200 OK)**:
    ```json
    {
      "token": "new_access_token_jwt"
    }
    ```

### POST /api/auth/logout
*   **Auth**: Protected
*   **Response (200 OK)**:
    ```json
    {
      "message": "Logged out successfully"
    }
    ```
    *   *Clears Cookie*: `refresh_token`

---

## 2. User Endpoints

### PATCH /api/user/edit
*   **Auth**: Protected
*   **Request Body**:
    ```json
    {
      "username": "New Username",
      "email": "newemail@example.com",
      "currentPassword": "OldPassword123",
      "newPassword": "NewPassword123"
    }
    ```
*   **Response (200 OK)**:
    ```json
    {
      "message": "User updated successfully"
    }
    ```

---

## 3. Spaces and Bookings Endpoints

### GET /api/bookings/spaces
*   **Auth**: Protected
*   **Response (200 OK)**: Array of Space objects.
    ```json
    [
      {
        "id": "1",
        "type": "desk",
        "name": "Shared Desk",
        "slug": "shared-desk",
        "description": "Flexible seating in our open workspace areas.",
        "imageUrl": "assets/imgs/spaces/shared2.jpg",
        "capacity": 7,
        "pricing": {
          "hourly": 40,
          "halfDay": 35,
          "day": 32
        }
      }
    ]
    ```

### GET /api/bookings/spaces/{id}
*   **Auth**: Protected
*   **Response (200 OK)**: Single Space object.

### GET /api/bookings/{spaceId}/availability/{date}
*   **Auth**: Protected
*   **Response (200 OK)**:
    ```json
    {
      "date": "2026-08-04",
      "slots": [
        { "hour": 9, "available": true },
        { "hour": 10, "available": false }
      ]
    }
    ```

### GET /api/bookings/{spaceId}/unavailable-dates/{year}/{month}
*   **Auth**: Protected
*   **Response (200 OK)**:
    ```json
    {
      "dates": ["2026-08-10", "2026-08-15"]
    }
    ```

### POST /api/bookings/availability
*   **Auth**: Protected
*   **Request Body**:
    ```json
    {
      "spaceId": "1",
      "date": "2026-08-04",
      "startTime": 9,
      "endTime": 17,
      "requestedUnits": 1
    }
    ```
*   **Response (200 OK)**:
    ```json
    {
      "available": true
    }
    ```

### POST /api/bookings/calculate-price
*   **Auth**: Protected
*   **Request Body**:
    ```json
    {
      "spaceId": "1",
      "plan": "Hourly",
      "date": "2026-08-04",
      "endDate": "2026-08-04",
      "startTime": 9,
      "endTime": 17,
      "quantity": 1
    }
    ```
*   **Response (200 OK)**:
    ```json
    {
      "price": 320
    }
    ```

### POST /api/bookings
*   **Auth**: Protected
*   **Request Body**:
    ```json
    {
      "spaceId": "1",
      "plan": "Hourly",
      "date": "2026-08-04",
      "endDate": "2026-08-04",
      "startTime": 9,
      "endTime": 17,
      "quantity": 1,
      "paymentMethod": "PAY_AT_VENUE"
    }
    ```
*   **Response (201 Created)**:
    ```json
    {
      "id": 101,
      "reference": "BK-A5B2F9C0",
      "spaceId": "1",
      "plan": "Hourly",
      "startAt": "2026-08-04T09:00:00Z",
      "endAt": "2026-08-04T17:00:00Z",
      "reservedUnits": 1,
      "totalPrice": 320,
      "status": "CONFIRMED",
      "paymentMethod": "PAY_AT_VENUE",
      "paymentStatus": "PENDING"
    }
    ```

### GET /api/bookings/me
*   **Auth**: Protected
*   **Response (200 OK)**: Array of Booking objects belonging to current user.

### PATCH /api/bookings/{id}/cancel
*   **Auth**: Protected
*   **Response (200 OK)**:
    ```json
    {
      "message": "Booking cancelled successfully"
    }
    ```

---

## 4. Dashboard Endpoints

### GET /api/dashboard/stats
*   **Auth**: Protected
*   **Response (200 OK)**:
    ```json
    {
      "totalReservations": 3,
      "upcomingReservations": 1,
      "completedReservations": 1,
      "cancelledReservations": 1,
      "totalVisits": 15,
      "totalPoints": 0
    }
    ```
