---
name: file_upload
description: >-
  File upload attacks — webshells, filename traversal writes, content-type/filename
  swaps, zip/polyglot/parser RCE (ImageMagick, Ghostscript), stored XSS via SVG/HTML,
  upload-from-URL SSRF pivot, CSV formula injection, open-bucket policy gaps.
  Auto-invoke when: multipart upload forms, avatar/attachment/import features, parser
  processing (thumbnail/resize/convert), upload endpoints in JS/API maps. Do NOT load
  for: no-upload surfaces embedding files elsewhere → `rce`; URL-picker uploads → `ssrf`.
family: sink-signal
severity: high → critical
---

# File Upload — validation gaps → webshell · write · parser RCE

> **Arsenal:** arbitrary file upload-and-serve (webshell), arbitrary file WRITE via
> traversal names, parser-library RCE, stored-XSS springboards, internal SSRF.
> **Sibling:** `rce` (write→execute), `ssrf` (upload-from-URL), `xss` (SVG/HTML stored),
> `access-control` (uploaded-object access), `deserialization` (payload delivery).
> **Proof bar:** uploaded file executed/read-back with observable effect (webshell 200 on
> request, DNS callback from parser, file overwritten). Upload "success" is `possible`.
> **Setup:** one upload field + the response/UI path where files are served.

## WAF Bypass (upload)
- Extension: case `.PhP`, double `shell.php.jpg`, trailing dot/space, null byte `%00`, `shell.phtml/.php5/.pht`, `.htaccess`/`web.config` override
- Content-Type swap: rename `shell.jpg` + `Content-Type: image/jpeg` → executed by server-side mapping (.jpg+PHP is env-dependent)
- Polyglots: PHP-in-GIF/JPEG/PDF (GIFAR), ZIP with `.php` then extraction normalizes (zip allows any entry name)
- Filename param ripping: some parsers sanitize FILENAME only, not the multipart `filename=` param — double param
- Chunked/whitespace: `shell.php ` truncated by filesystems; `shell.php./` ; unicode `.php‎` ZWJ tricks
- Multipart parser confusion: one part passes check, another (identical name) contains the payload

## Context
- Map the lifecycle: WHERE is validation (extension? magic bytes? size?), WHERE it lands (webroot?
  S3? private dir?), WHO processes it (just serves? thumbnail? OCR? convert? ffmpeg? unzip?), and
  WHO renders it. Every bug is a mismatch between these moments.

## General Techniques
- **No validation:** upload `.php`/`.jsp`/`.aspx`/`.war`/`.cgi` → direct webshell where served
- **Content-type swap:** JPG-typed PHP executes when server inspects header only
- **Filename traversal write:** `../../var/www/x.php`, `..%2f..%2f.config` — overwrite config/htaccess/authorized_keys
- **Extension allowlist bypass:** `.php` → `.phtml` `.php3` `.php4` `.php5` `.pht` `.shtml` `.asp` `.aspx` `.jspx` `.war`
- **Apache handler tricks:** `.htaccess` with `AddType application/x-httpd-php .jpg`; `.user.ini` auto_prepend
- **IIS/Nginx:** `shell.asp;.jpg`, `shell.aspx%00.jpg`, Nginx `shell.php%0a.jpg` variants
- **Parser RCE:** ImageMagick (MVG/MSL ImageTragick), Ghostscript (CVE-2023-36664), ffmpeg HLS/AVI exploits, ExifTool binaries (CVE-2021-22204)
- **SVG/HTML stored XSS:** upload raw SVG/HTML served same-origin → victim-context JS
- **SVG SSRF/IMDS:** SVG with `<image href="http://169.254.169.254/...">` fetched by server-side rasterizer
- **Upload-from-URL:** server fetches URL → SSRF (→ `ssrf`), file saved → second sink
- **Polyglot PHAR:** GIF/JPEG+PHAR → any file-function triggers deserialize (→ `deserialization`)
- **ZIP slip:** upload archive with `../` entries → overwrite on extraction (→ `rce`)
- **CSV/XLSX formula injection:** `=cmd|'/c calc'!A0`, `@SUM(...)` — fires in victim's Excel (export→RCE on analyst)
- **Cloud policy gaps:** open bucket write/list (S3 ACL, presigned abuse), prefix-escape path tricks (→ `recon-cloud`)
- **Pixel flood / decompression bomb:** DoS via huge compressed uploads (low sev, reportable)
- **Error leakage:** resize of invalid file → absolute paths in stack traces (→ `info_disclosure`)

## Second-Order & Bypass Techniques
- Upload TOCTOU: content validated once on save, replaced before execution (race window) — two parallel uploads same name (→ `race_condition`)
- Filename → SQL/cmd/log sinks: `'; DROP TABLE…--.png` filenames logged into queries
- Upload lands in private dir → find ANY reflection of user-controlled filename in responses to probe traversal read

## Auth Bypass Techniques
- Uploaded object served without authz → predict/iterate object URLs to read other clients' files (→ `access-control`)
- HTML/PDF upload to admin-review queue → admin session XSS (stored XSS → admin ATO)

## Header Techniques
- `X-Filename`/`Content-Disposition` parser mismatches → traversal via header instead of multipart name
- Chunked uploads: bypass content-length/size limits for decompression-bomb DoS

## CVE on Sight
| CVE | Surface | Class |
|---|---|---|
| CVE-2023-36664 | Ghostscript ≤ 10.0.0 | parser RCE (no validation) |
| CVE-2021-22204 | ExifTool < 12.24 | DjVu parser RCE |
| CVE-2016-3714 (ImageTragick) | ImageMagick < 6.9.3-10 | MVG RCE |
| CVE-2020-8127 | jQuery.uploadFile | deserialization RCE via upload |
| CVE-2021-37012 | Lexmark | webshell upload (rare family) |

## Indicators — record as `possible` when seen
- `multipart/form-data` fields: avatar, attachment, import, document, file, image, media, upload
- Response serves the file back (uploads stored webroot) · parser endpoints (resize/thumbnail/convert/ocr/unzip) touching uploads
- Filename reflected in responses or logs · URL-of-file upload fields (from-URL pickers)
- .env/.config/export handlers accepting filenames (write sinks)

## Tools
- `curl -s -F 'file=@shell.php;filename=shell.jpg;type=image/jpeg' URL/upload` then request `/uploads/shell.jpg`
- `php -r` only against YOUR local PHP to build polyglots (create once, test remotely)
- ffuf extension battery: `-w ext.txt -u 'URL/upload' -F 'file=@shellFUZZ'`; nuclei `-tags file-upload`
- Burp: multipart parser confusion macro; `exiftool -jpeg` embedding for IM/ExifTool attempts (test on lab servers)