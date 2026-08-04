# TVS Spaces Frontend Verification

## Branch

`feature/tvs-functional-e2e`

## Implemented integration

- Environment-driven API base URL.
- Safe access-token and refresh-token lifecycle.
- Live workspace catalog and slug-based detail pages.
- Live availability and server-authoritative pricing.
- Persisted pay-at-venue checkout.
- Real booking history, dashboard metrics, cancellation, and logout.
- No client-side password persistence, fake card payment, fake enquiry success, or hardcoded booking/dashboard data.

## Automated gate

The permanent GitHub Actions workflow performs:

```text
npm ci
npm run build
npm test -- --watch=false --browsers=ChromeHeadless
```

The feature branch must keep this gate green before the draft pull request is marked ready.

## Runtime dependency

The production Angular build requires a reachable Spring Boot API matching backend pull request `shawky2002020/TvsSpaces-back#1`. The production API URL or reverse proxy must be configured during deployment.
