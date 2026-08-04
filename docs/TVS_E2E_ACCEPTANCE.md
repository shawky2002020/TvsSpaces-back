# TVS Spaces E2E Acceptance Scenarios

This document specifies the validation criteria for manual and automated test verification.

## 1. Scenario: User Registration and Login
*   **Action**: Go to `/auth/register`, enter email `jane@example.com`, username `Jane`, password `Password123!`, userType `Individual`. Submit.
*   **Result**: Alert "registered successfully". Redirects to `/dashboard`.
*   **Action**: Refresh the page.
*   **Result**: Dashboard page remains loaded and user remains authenticated (transient session is restored via cookie-based token refresh).
*   **Action**: Log out.
*   **Result**: Redirects to `/auth/login`. Local token cache and storage are cleared.

## 2. Scenario: Viewing Spaces & Real-Time Availability
*   **Action**: Go to Spaces list (`/dashboard/booking`).
*   **Result**: Displays active co-working spaces loaded from the server database (e.g. Shared Desk, Solo Desk, Team Room) instead of static mockup lists.
*   **Action**: Select "Shared Desk", click "Next".
*   **Result**: Date-picker grid is loaded. Displays slots (9:00 to 18:00) with checkmarks or crossmarks showing real-time availability fetched from the backend.

## 3. Scenario: Successful Persisted Booking
*   **Action**: Select plan `Hourly` or `Daily`, choose an available date, start/end hour, quantity `1`. Review EGP price. Click "Next".
*   **Result**: Advances to Booking Summary page. Displays selected slot, space details, and EGP price.
*   **Action**: Click "Proceed to Checkout", select payment method "Pay at Venue", click "Pay Now".
*   **Result**: Submits booking. Shows payment success loader. Redirects to `/dashboard`.
*   **Result**: The new booking appears in the "Recent Bookings" table on the Dashboard with status `CONFIRMED`, and stats cards increment.

## 4. Scenario: Conflicting Booking Rejection (Double Booking)
*   **Action**: Select the exact same space, date, time slot, and quantity exceeding the remaining space capacity. Attempt to book.
*   **Result**: Server returns validation error "Not enough capacity". Checkout displays appropriate warning and prevents duplicate booking persistence.
