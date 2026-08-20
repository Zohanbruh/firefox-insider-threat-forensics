# SQL query reference

Every query the toolkit runs against evidence, what it means, and the pitfalls
each one avoids. An examiner should be able to explain any finding using this
page; an opposing expert should be able to reproduce it in DB Browser for
SQLite or `sqlite3`.

**Timestamps.** Firefox stores most times as **PRTime** — microseconds since
the Unix epoch. `moz_cookies.expiry` is an exception and uses whole seconds.
The examples below include `datetime(...)` conversions for manual use, but the
toolkit converts in Python against an explicit timezone instead (see the
warning at the end).

---

## places.sqlite

### URL history

```sql
SELECT id, url, COALESCE(title, '') AS title, visit_count,
       COALESCE(typed, 0) AS typed, last_visit_date,
       COALESCE(frecency, 0) AS frecency
FROM moz_places
ORDER BY last_visit_date DESC;
```

`moz_places` holds one row per **distinct URL**, not per visit. `visit_count`
is a running total; `typed = 1` means the URL was entered in the address bar at
least once. `last_visit_date` is `NULL` for URLs known to the browser but never
visited (bookmark imports, for example) — a distinction that matters when a
subject claims they never opened a page.

### Individual navigation events

```sql
SELECT v.id AS visit_id, v.place_id, p.url, COALESCE(p.title, '') AS title,
       v.visit_date, v.visit_type, COALESCE(v.from_visit, 0) AS from_visit
FROM moz_historyvisits v
JOIN moz_places p ON p.id = v.place_id
ORDER BY v.visit_date DESC;
```

Use an explicit `JOIN ... ON`. The older comma form
(`FROM moz_places, moz_historyvisits WHERE ...`) produces a cartesian product
if the join predicate is ever dropped during editing — silently inflating an
evidence table.

`from_visit` chains a visit to the one that caused it, which is how a redirect
sequence or a click path is reconstructed.

### Visit types

```sql
SELECT visit_type, COUNT(*) AS n
FROM moz_historyvisits
GROUP BY visit_type;
```

| Code | Meaning | Evidential weight |
|---|---|---|
| 1 | Link followed | Deliberate, but the target was chosen by the page |
| 2 | Typed, or selected from address-bar suggestions | **Strongest** — a deliberate act by the user |
| 3 | Bookmark opened | Deliberate; implies prior retention |
| 4 | Embedded resource | Not a user action at all |
| 5 | Permanent redirect (301) | Server-driven; **not** a user action |
| 6 | Temporary redirect (302) | Server-driven; **not** a user action |
| 7 | Download | |
| 8 | Framed link | |
| 9 | Reload | |

Codes 5 and 6 are the ones most often misread. A subject who lands on a page
through a redirect never chose that URL, and a report that counts redirects as
deliberate navigation overstates its case.

Note that code 2 covers both typing a URL in full *and* selecting an
autocomplete suggestion after a few characters — worth stating precisely.

### Search queries

```sql
SELECT p.url, p.title, p.last_visit_date
FROM moz_places p
WHERE p.url LIKE '%google.com/search%' AND p.url LIKE '%q=%'
ORDER BY p.last_visit_date DESC;
```

The toolkit extracts the term from the query parameter and decodes it, rather
than matching on the title, because titles are truncated and localised.

> **Pitfall the toolkit guards against.** `https://www.google.com/url?q=…` and
> `https://www.google.com/aclk?…` also carry a `q` parameter — but they are
> *redirectors* holding a destination URL, not searches. Matching on the host
> alone records every ad click and outbound redirect as "a search the subject
> performed". The parser requires the path to be `/search` and rejects values
> that are themselves URLs. See `tests/test_places_parser.py`.

### Video activity

```sql
SELECT p.url, p.title, v.visit_date
FROM moz_places p
JOIN moz_historyvisits v ON p.id = v.place_id
WHERE p.url LIKE '%youtube.com/watch?%'
ORDER BY v.visit_date DESC;
```

The `LIKE` pattern is passed as a **bound parameter** in the toolkit, never
concatenated.

### Bookmarks

```sql
SELECT b.id, b.parent, COALESCE(b.title, '') AS title, b.type,
       COALESCE(p.url, '') AS url, b.dateAdded, b.lastModified
FROM moz_bookmarks b
LEFT JOIN moz_places p ON p.id = b.fk
ORDER BY b.lastModified DESC;
```

`type = 1` is a bookmark, `type = 2` a folder. Use `LEFT JOIN`: an inner join
drops every folder row, and folders carry the structure that makes a bookmark
list legible. The toolkit walks `parent` to build a folder path.

A bookmark is evidentially interesting because it is an act of **retention** —
the user chose to keep the resource for later, which is harder to explain as an
accidental visit.

### Downloads

```sql
SELECT a.place_id, n.name AS attribute, a.content, a.dateAdded, a.lastModified, p.url
FROM moz_annos a
JOIN moz_anno_attributes n ON n.id = a.anno_attribute_id
LEFT JOIN moz_places p ON p.id = a.place_id
WHERE n.name LIKE 'downloads/%';
```

Modern Firefox records downloads as annotations:
`downloads/destinationFileURI` holds the saved path, and `downloads/metaData`
holds a small JSON blob with `endTime` (**milliseconds**, unlike everything
else) and `fileSize`. Older profiles used a separate `downloads.sqlite`.

---

## cookies.sqlite

```sql
SELECT id, host, name, path, isSecure, isHttpOnly, sameSite,
       creationTime, lastAccessed, expiry
FROM moz_cookies
ORDER BY lastAccessed DESC;
```

Cookies corroborate history: a cookie whose `lastAccessed` falls inside the
activity window shows the domain was genuinely loaded in the browser, which is
harder to explain away than a URL that could have been auto-suggested.

> **Pitfall.** `expiry` is in **seconds**, while `creationTime` and
> `lastAccessed` are in **microseconds**. Applying the microsecond conversion to
> `expiry` pushes it roughly fifty thousand years into the future — an error
> that is obvious once seen and easy to miss in a table of hundreds of rows.
> Tested by `test_expiry_is_parsed_as_seconds_not_microseconds`.

Older profiles have no `sameSite` column; the parser inspects the schema first
and substitutes a default rather than failing.

---

## formhistory.sqlite

```sql
SELECT id, fieldname, value, COALESCE(timesUsed, 0) AS timesUsed,
       firstUsed, lastUsed
FROM moz_formhistory
ORDER BY lastUsed DESC;
```

This is the strongest browser-side artefact for **authorship**. History can be
populated by a redirect, a suggestion or a link click; a `moz_formhistory` row
means text was physically entered into a form or the search bar.

`timesUsed` shows repetition, which distinguishes an idle look from a term
someone returned to. `fieldname = 'searchbar-history'` is the search bar
widget; other field names come from forms on individual sites, and can include
personal data outside the scope of an examination — extract only what the
authority covers.

The toolkit cross-references form history against recovered search terms:
anything in both is reported as confirmed keyboard entry.

---

## Timestamp conversion

For manual work in DB Browser for SQLite:

```sql
SELECT datetime(last_visit_date / 1000000, 'unixepoch') AS utc_time
FROM moz_places;
```

> **Do not use `'localtime'` in an evidential query.**
>
> ```sql
> -- Reproducible only on the machine that ran it:
> SELECT datetime(last_visit_date / 1000000, 'unixepoch', 'localtime') FROM moz_places;
> ```
>
> `'localtime'` resolves against the **examiner's** machine timezone, not the
> subject system's. The same query run by a reviewer in another country returns
> different times with no warning and no record of which zone was used.
>
> Convert to UTC in SQL, and render local time explicitly:
>
> ```bash
> ffxforensics analyze evidence/ -o results --tz +01:00
> ```
>
> Every generated report states the timezone it was rendered in, in its header.
