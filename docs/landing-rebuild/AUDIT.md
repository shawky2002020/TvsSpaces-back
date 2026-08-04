# TVS Spaces — landing page audit (pre-rebuild)

Captured on branch `feature/landing-page-rebuild`, against the running Angular dev server
(`localhost:4200`) and the running Spring Boot backend (`localhost:8080`, MySQL in Docker).

Before screenshots: `docs/landing-rebuild/before/` (390×844, 768×1024, 1366×768, 1440×900, 1920×1080).

---

## 1. What the product actually is (verified against the backend, not assumed)

Source of truth: `server/src/main/java/org/example/spacesback/service/BookingService.java`,
`model/Space.java`, `dto/response/SpaceResponse.java`, `resources/db/migration/V1__init_schema.sql`,
and a live `GET /api/bookings/spaces`.

**Inventory — 5 spaces, one location.**

| id | type | name | capacity (bookable units) | hourly | half-day | day |
|---|---|---|---|---|---|---|
| 1 | desk | Shared Desk | 7 | 40 | 35 | 32 |
| 2 | desk | Solo Desk | 1 | 50 | 45 | 42 |
| 3 | desk | PC Station | 3 | 60 | 55 | 52 |
| 4 | room | Team Room | 1 | 120 | 115 | 110 |
| 5 | room | Big Meeting Room | 1 | 200 | 190 | 185 |

Currency is EGP (used consistently in `space-card`, `desk-detail`, `room-detail`, `checkout`,
`booking-summary`).

**Pricing semantics — the three numbers are NOT the same unit.** From `calculatePriceInternal`:

- `Hourly` → `hourlyPrice × hours × quantity` — a per-hour rate.
- `Half-day` → `halfDayPrice × quantity` — a **flat** rate for a 4-hour block.
- `Daily` → `dayPrice × inclusiveDays × quantity` — a **flat** rate per day.
- `Monthly` → `dayPrice × 20 × quantity`.

So "40 / 35 / 32" for a Shared Desk means *40 per hour*, *35 for a half day*, *32 for a full day*.
Rendering them as a single ladder without units would misrepresent the product. Every price on the
new page carries its unit.

**Opening hours.** `OPENING_HOUR = 9`, `CLOSING_HOUR = 18`. A `Daily` booking is normalised to
09:00–18:00. A `Half-day` with no explicit times is normalised to 09:00–13:00. Availability is
computed hour-by-hour.

**Capacity semantics.** `isAvailable` rejects `requestedUnits > space.getCapacity()`. Capacity is the
number of **units bookable at the same time**, not seats in a room. Shared Desk capacity 7 = seven
desks. Team Room capacity 1 = one room. The old page printed "Up to 14 Guests (16 sqm room)" — that
number exists nowhere in the backend and is not reproduced.

**Auth.** `POST /api/bookings` requires `Authentication`; `/api/bookings/spaces*` is public. So the
catalogue can be browsed anonymously and the booking flow is gated at `/dashboard/**` by `AuthGuard`.

**Real booking journey.** `/desks/:slug` or `/rooms/:slug` → `selectPlan()` writes the selection →
`/dashboard/booking/dates` → date/plan picker → summary → checkout. `paymentMethod` is a field on
`BookingRequest`; there is no payment gateway integration.

**Limitations found.** No reviews/ratings entity. No user counts. No partner/tenant records. No
multi-location model (`Space` has no location column — the single address lives only in markup). No
cancellation-window rule (`cancelBooking` just flips status). Therefore: no ratings, testimonials,
counters, partner logos, awards, or multi-city claims can be shown honestly.

---

## 2. Section-by-section audit

| Current section | Current purpose | Problem | User impact | Decision |
|---|---|---|---|---|
| Header | Global nav | Nav is 4 in-page anchors (`#home`, `#about`, `#desks`, `#contact`) that break from any other route. Single "Get Started" button pointing at `/auth/login`. No authenticated state. Mobile menu opens but never traps focus, has no `aria-expanded`, and closes only via its own X. | Nav dead-ends off the home route; keyboard and screen-reader users can get stranded in the mobile menu. | **Rebuild** |
| Hero | Value proposition | Standard text-left / image-right template. Copy ("Your Next High-Performance Workspace", "Join a thriving community…") is generic and says nothing about booking, time, or price. `Book a Space` routes to `/dashboard/booking`, which is `AuthGuard`-ed, so an anonymous visitor is bounced to login with no explanation. | Visitor cannot tell what is bookable, for how long, or at what price. Primary CTA leads to a login wall. | **Rebuild** |
| Logo wall | Social proof | **Fabricated.** Vercel, Stripe, GitHub, Notion under "TRUSTED BY TEAMS & FREELANCERS AT". No such relationships exist in the product. | Actively misleading. | **Remove** |
| About / story | Brand trust | Duplicated string: "Your Productive Haven Your Productive Haven in Heliopolis". Founding-year and growth claims ("born amidst global change", "thriving community hub") are unverifiable from any source in the repo. | Visible copy bug; unsupported claims. | **Remove** (address and hours preserved, moved to trust + footer) |
| Features ("Why Choose Us") | Differentiation | Four identical icon-heading-text cards over a washed-out parallax photo. Claims a "99.9% uptime guarantee" and "24/7 Access" — the backend closes at 18:00, so 24/7 is contradicted by the code. | Generic; one claim is false. | **Replace** with work-scenario section driven by real space types |
| Amenities | Facility detail | Hardcoded list that does not match `space_amenities` in the database. Includes "Phone Booths", "Events Space", "Printing & Scanning" which exist in no record. | Invented inventory. | **Replace** — amenities now read from the API per space |
| Desk options | Catalogue | Three cards with **hardcoded** feature lists identical across all three, no image, no price, no capacity. Links use `spaces[0].slug` / `[1]` / `[2]` — positional indexes into the API response, which breaks if the API returns a different order or fewer rows. | No price or capacity anywhere on the page; fragile links. | **Rebuild** on real data |
| Gradient divider | Visual break | Full-viewport band containing only the sentence "Step inside where ideas awaken and energy becomes action." Marked up as `<h1>`, so the page has two `<h1>`s. | Wasted viewport; heading-order violation. | **Remove** |
| Room options | Catalogue | Same problems as desks, plus a "Popular" badge with no supporting data and the invented "Up to 14 Guests (16 sqm room)". | Fabricated capacity. | **Rebuild** on real data |
| CTA | Conversion | Two `<button>`s ("Book a Tour", "Contact Us") with **no** click handler and no `routerLink`. They do nothing. | Dead primary conversion point. | **Rebuild** |
| Contact | Contact details | Real address/phone/email, but `<a call="...">` and `<a mailto="...">` are invalid attributes — these render as non-functional links with no `href`. | Phone and email are not clickable and are not exposed as links to assistive tech. | **Rebuild** (fix to `tel:` / `mailto:`) |
| Footer | Navigation | 11 links with `href="#"`, including invented products ("Hot Desking", "Conference Hall", "Private Office", "Virtual Tour"). Four social icons all `href="#"`. Legal links to nothing. | Every footer link is dead; several imply inventory that does not exist. | **Rebuild** |

---

## 3. Cross-cutting problems

**Typography.** `$font-family-base: 'base'` — there is **no `@font-face` for `base`**, so all body copy
silently falls back to Arial. Meanwhile `h3` and `.section-tag` use `accent` = *Aleyna Personal Use*,
a handwriting script, which is why "Shared Desk", "PC Station" and "High-Speed Internet" render in a
casual script on a business booking page. `h1` uses *honfleur*, `h2` uses *tafel-sans-pro* — three
decorative faces, none of them loaded for body text, no weight range (all Regular), sizes fixed in
`px` with only two breakpoint overrides.

**Colour.** `$primary-grad`, `$secondary-grad`, `$light-grad`, `$hero-grad` layer all six brand colours
into multi-stop gradients used as large surfaces. The accent cyan `#00DFE4` is used decoratively
(underlines, gradients) so it carries no meaning. Nothing in the palette signals availability or
selection — the two states this product is actually about.

**Data integrity.** `HomeComponent` seeds `spaces` with five empty `{slug:''}` placeholders so the
template's `spaces[0..4]` index references do not throw while loading. Cards render with dead links
during load, and the hardcoded card content never matches the data that eventually arrives.

**Accessibility.** Two `<h1>`s. `h3` used for card titles under `h2` in some places and over nothing in
others. Mobile menu toggle is a `<div>` with a click handler — not focusable, not a button, no
`aria-expanded`, no focus trap, no Escape. Decorative background images have `alt=""` (correct) but
the hero image alt is generic. No visible focus styling beyond browser default, which disappears
against the dark hero. `.section-tag` is an eyebrow on every section.

**Motion / performance.** `initParallaxEffect()` attaches a raw `window.addEventListener('scroll')`
that writes `style.transform` on every frame for every parallax image — layout-adjacent work on the
main thread, and it runs regardless of `prefers-reduced-motion`. Hero image is `assets/imgs/5.jpg` at
**1.9 MB**; `7.jpg` is 4.9 MB. No `width`/`height`, no `loading="lazy"`, no `decoding="async"`,
no responsive sources → guaranteed layout shift and a very slow LCP.

**Responsive.** No horizontal overflow at any tested viewport (the one thing that is fine). But the
mobile page is **9,334 px** tall for a five-space catalogue, the hero image is hidden entirely below
`sm`, and the parallax sections keep full-bleed photos behind translucent cards, leaving card text at
roughly 2:1 contrast in places.

---

## 4. Keep / rebuild / remove

**Preserve**
- Routes: `/`, `/desks/:slug`, `/rooms/:slug`, `/auth/login`, `/auth/register`, `/dashboard/**`.
- `BookingService` and all its endpoints; `AuthService` session shape.
- Brand palette hues, the logo assets, and the real workspace photography in `assets/imgs/spaces/`.
- The real contact facts: Office 9, 94 Fareed Smeika, Heliopolis, Cairo; +20 105 506 6838;
  support@tvsspaces.com; the Google Maps link.

**Rebuild** — header, hero, catalogue, process, conversion, contact, footer.

**Remove** — fabricated logo wall, unverifiable brand story, invented amenity and feature lists,
invented room capacities, the "24/7 access" and "99.9% uptime" claims, the empty gradient divider,
the dead CTA buttons, all `href="#"` links, the scroll-listener parallax.

**Move** — address/hours from the contact section into the trust section (where they support a
booking decision) and the footer (where they are reference information).
