# Ebook Store - Systems 1 through 8

Flask backend implementing authentication, content, secure download delivery, personalization, admin operations, and discovery/SEO.

## System 8 (Search, Filtering & SEO) highlights
- Search over title, author, description, category context, and keywords.
- Real-time suggestions endpoint: `GET /search/suggestions?q=...`
- Ranked search behavior in `GET /ebooks` (`title > author > description`) with:
  - partial matching
  - combined filters (`category`, `author`, `featured`, `min_rating`, `recent_days`)
  - pagination (`page`, `per_page`)
  - sort modes (`newest`, `highest_rated`, `most_downloaded`, `alphabetical`)
- Search analytics logging (`search_query_logs`) and admin analytics endpoint:
  - `GET /admin/search-analytics`
  - includes most searched terms and zero-result terms.
- SEO-friendly slug support for ebooks via `ebook.slug` and `GET /ebook/<slug>` payload with:
  - meta title
  - meta description
  - canonical URL
  - structured data (Book + AggregateRating).
- Sitemap endpoint: `GET /sitemap.xml` with homepage/category/ebook URLs.
- Cached category page endpoint: `GET /categories/<slug>/ebooks` (short-lived cache).
- Social share payload endpoint: `GET /ebooks/<id>/share` (ebook/preview/review share links only, never file URLs).

## Existing systems (1-7) retained
- Auth, admin auth, session security, captcha/rate-limits.
- Ebook/category/file/version management.
- Code generation/validation and secure code-gated delivery.
- Reviews/ratings + analytics.
- Favorites + user/admin download history views.
- Admin dashboard, exports, reports, backups, notifications, maintenance mode, error logs.

## Key tables (new for System 8)
- `search_query_logs`
- `ebooks.slug`
- `ebooks.keywords`

## Run
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```
