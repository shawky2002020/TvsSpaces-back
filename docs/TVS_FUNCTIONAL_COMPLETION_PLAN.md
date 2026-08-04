# TVS Spaces Functional Completion Plan

## 1. Verified Repository State
*   **Client**: `feature/tvs-functional-e2e` branch. Baseline commit: `a016a9f` (spaceX done). Local change: `src/app/app-routing-module.ts` has `LicenseGuard` commented out.
*   **Server**: `feature/tvs-functional-e2e` branch. Baseline commit: `99aae29` (user edit setup). Local change: `pom.xml` has self-dependency removed.

## 2. Phase Breakdown and Task Matrix

| Phase | Task ID | Description | Files Expected to Change | Risk | Dependencies |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Phase 0** | `TS-P0-01` | Fix Angular Karma/Sass config & starter test assertions | `client/angular.json`, `client/src/app/app.spec.ts` | Low | None |
| **Phase 1** | `TS-P1-01` | Config profiles & setup MySQL connection | `server/src/main/resources/application*.properties`, `server/compose.yaml` | Medium | None |
| **Phase 2** | `TS-P2-01` | Flyway configuration and initial schema migration | `server/pom.xml`, `server/src/main/resources/db/migration/*.sql` | High | Phase 1 |
| **Phase 3** | `TS-P3-01` | Secure authentication responses and refresh logic | `server/src/main/java/org/example/spacesback/controller/AuthController.java`, `server/src/main/java/org/example/spacesback/controller/UserController.java`, `client/src/app/core/auth/auth.service.ts` | High | Phase 2 |
| **Phase 4** | `TS-P4-01` | Implement Space & Booking entities, repos, services, and APIs | `server/src/main/java/org/example/spacesback/model/*.java`, `server/src/main/java/org/example/spacesback/controller/*.java` | High | Phase 3 |
| **Phase 5** | `TS-P5-01` | Implement transactional validation (overlap check, locks) | `server/src/main/java/org/example/spacesback/service/BookingService.java` | High | Phase 4 |
| **Phase 6** | `TS-P6-01` | Angular client routing, checkout integration, and state fixes | `client/src/app/features/booking/**/*.ts`, `client/src/app/app-routing-module.ts` | Medium | Phase 5 |
| **Phase 7** | `TS-P7-01` | Dashboard stats API connection and missing sidebar pages | `client/src/app/features/dashboard/**/*.ts`, `client/src/app/shared/components/side-bar/side-bar.ts` | Medium | Phase 6 |
| **Phase 8** | `TS-P8-01` | Add unit, integration, and E2E validation tests | `server/src/test/**/*.java`, `client/src/**/*.spec.ts` | Medium | Phase 7 |
| **Phase 9** | `TS-P9-01` | Production deployment setup and documentation check | `server/Dockerfile`, `README.md` | Low | Phase 8 |

## 3. Definition of Done
The project is complete when:
*   Frontend and backend compile cleanly.
*   All unit, integration, and E2E tests pass.
*   Full client-to-server-to-database booking flow works.
*   Sessions survive page reloads.
*   Booking conflicts beyond capacity are transactionally rejected on the server.
*   No secrets are hardcoded or passwords logged in plaintext.
