// =============================================================================
//  web_auth_logic.h - the string handling behind the portal's access control.
//
//  Header-only and free of Arduino types on purpose: every function here takes
//  attacker-controlled input (headers, form fields, URLs), so it has to be
//  testable on a desktop compiler with sanitizers, without a board attached.
//  The Arduino glue (sessions, NVS, routes) lives in web_auth.cpp.
// =============================================================================
#pragma once

#include <stddef.h>
#include <stdint.h>
#include <string.h>

// ---------------------------------------------------------------------------
//  Constant-time comparison
// ---------------------------------------------------------------------------
inline bool waCtEqual(const uint8_t* a, const uint8_t* b, size_t n) {
  volatile uint8_t diff = 0;
  for (size_t i = 0; i < n; i++) diff = diff | (uint8_t)(a[i] ^ b[i]);
  return diff == 0;
}

// Compare a candidate against a secret without an early exit on the first
// wrong character. Only the secret's length can leak, and for the device
// password that length is fixed and public.
inline bool waCtStrEqual(const char* candidate, const char* secret) {
  if (!candidate || !secret) return false;
  const size_t cl = strlen(candidate), sl = strlen(secret);
  if (sl == 0) return false;               // an unset secret matches nothing
  volatile uint8_t diff = (uint8_t)(cl != sl);
  for (size_t i = 0; i < sl; i++) {
    const uint8_t c = (i < cl) ? (uint8_t)candidate[i] : 0;
    diff = diff | (uint8_t)(c ^ (uint8_t)secret[i]);
  }
  return diff == 0;
}

// ---------------------------------------------------------------------------
//  Hex
// ---------------------------------------------------------------------------
inline void waBytesToHex(const uint8_t* in, size_t n, char* out) {  // out: 2n+1
  static const char digits[] = "0123456789abcdef";
  for (size_t i = 0; i < n; i++) {
    out[2 * i]     = digits[in[i] >> 4];
    out[2 * i + 1] = digits[in[i] & 0x0F];
  }
  out[2 * n] = '\0';
}

// Exactly 2*outBytes lower-case hex digits - the one form waBytesToHex writes.
// Nothing more, nothing less, no other spelling of the same value.
inline bool waHexToBytes(const char* hex, uint8_t* out, size_t outBytes) {
  if (!hex || strlen(hex) != outBytes * 2) return false;
  for (size_t i = 0; i < outBytes * 2; i++) {
    const char c = hex[i];
    uint8_t v;
    if (c >= '0' && c <= '9')      v = (uint8_t)(c - '0');
    else if (c >= 'a' && c <= 'f') v = (uint8_t)(c - 'a' + 10);
    else return false;
    if (i & 1) out[i / 2] = (uint8_t)(out[i / 2] | v);
    else       out[i / 2] = (uint8_t)(v << 4);
  }
  return true;
}

// ---------------------------------------------------------------------------
//  Cookie header: "a=1; bh_sid=abc; c=3"
//
//  The name has to start a pair - "xbh_sid=" must not match - and the value
//  has to fit, or the cookie is treated as absent rather than truncated.
// ---------------------------------------------------------------------------
inline bool waCookieValue(const char* header, const char* name, char* out, size_t outLen) {
  if (!header || !name || !out || outLen == 0) return false;
  out[0] = '\0';
  const size_t nameLen = strlen(name);
  if (nameLen == 0) return false;

  const char* p = header;
  while (*p) {
    while (*p == ' ' || *p == '\t' || *p == ';') p++;      // start of a pair
    if (!*p) break;
    const char* end = strchr(p, ';');
    if (!end) end = p + strlen(p);
    if ((size_t)(end - p) > nameLen && strncmp(p, name, nameLen) == 0 && p[nameLen] == '=') {
      const char* v = p + nameLen + 1;
      const char* ve = end;
      while (ve > v && (ve[-1] == ' ' || ve[-1] == '\t')) ve--;
      const size_t vl = (size_t)(ve - v);
      if (vl >= outLen) return false;
      memcpy(out, v, vl);
      out[vl] = '\0';
      return true;
    }
    p = end;
  }
  return false;
}

// ---------------------------------------------------------------------------
//  Same-origin check
//
//  A browser states where a request came from in Origin (and, on older ones,
//  Referer). The portal only ever calls itself, so anything else is another
//  site driving the user's browser. Comparing against the Host the request was
//  addressed to - rather than a list of names - keeps this working behind any
//  IP, mDNS or router-assigned name.
// ---------------------------------------------------------------------------
inline char waLower(char c) { return (c >= 'A' && c <= 'Z') ? (char)(c + 32) : c; }

// Case-insensitive compare of a[0..an) with b[0..bn).
inline bool waIEqualN(const char* a, size_t an, const char* b, size_t bn) {
  if (an != bn) return false;
  for (size_t i = 0; i < an; i++) if (waLower(a[i]) != waLower(b[i])) return false;
  return true;
}

// Length of `s` (n bytes) without a trailing ":80".
inline size_t waStripDefaultPort(const char* s, size_t n) {
  return (n > 3 && memcmp(s + n - 3, ":80", 3) == 0) ? n - 3 : n;
}

// "http://<host>" must be exactly the Host header.
inline bool waOriginMatchesHost(const char* origin, const char* host) {
  if (!origin || !host || !host[0]) return false;
  if (strncmp(origin, "http://", 7) != 0) return false;    // also rejects "null"
  const char* o = origin + 7;
  const size_t on = waStripDefaultPort(o, strlen(o));
  const size_t hn = waStripDefaultPort(host, strlen(host));
  if (on == 0 || o[0] == ':' || host[0] == ':') return false;   // no host name at all
  return waIEqualN(o, on, host, hn);
}

// "http://<host>/..." - the authority part must be exactly the Host header.
inline bool waRefererMatchesHost(const char* referer, const char* host) {
  if (!referer || !host || !host[0]) return false;
  if (strncmp(referer, "http://", 7) != 0) return false;
  const char* a = referer + 7;
  size_t an = 0;
  while (a[an] && a[an] != '/' && a[an] != '?' && a[an] != '#') an++;
  an = waStripDefaultPort(a, an);
  const size_t hn = waStripDefaultPort(host, strlen(host));
  if (an == 0 || a[0] == ':' || host[0] == ':') return false;   // no host name at all
  return waIEqualN(a, an, host, hn);
}

// The decision. A header that is present has to agree; a client that sends
// neither (curl, a script) is not a browser being steered by another site, and
// still needs the session cookie.
inline bool waSameOrigin(const char* origin, const char* referer, const char* host) {
  if (origin && origin[0])   return waOriginMatchesHost(origin, host);
  if (referer && referer[0]) return waRefererMatchesHost(referer, host);
  return true;
}

// ---------------------------------------------------------------------------
//  Online-update URL
//
//  Exactly https://github.com/<repo>/releases/download/<tag>/<file>, with a
//  file built for this board. Everything after the prefix is held to a plain
//  character set, so no "..", query string, userinfo or encoding trick can
//  walk the request to another repository.
// ---------------------------------------------------------------------------
inline bool waOtaUrlAllowed(const char* url, const char* repo, const char* board) {
  if (!url || !repo || !board || !repo[0] || !board[0]) return false;
  const size_t ul = strlen(url);
  if (ul > 300) return false;

  static const char host[] = "https://github.com/";
  static const char mid[]  = "/releases/download/";
  const size_t hl = sizeof(host) - 1, rl = strlen(repo), ml = sizeof(mid) - 1;
  if (ul <= hl + rl + ml) return false;
  if (memcmp(url, host, hl) != 0) return false;
  if (memcmp(url + hl, repo, rl) != 0) return false;
  if (memcmp(url + hl + rl, mid, ml) != 0) return false;

  const char* rest = url + hl + rl + ml;          // "<tag>/<file>"
  const char* slash = nullptr;
  for (const char* p = rest; *p; p++) {
    const char c = *p;
    if (c == '/') {
      if (slash) return false;                    // one separator only
      slash = p;
      continue;
    }
    const bool plain = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                       (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-';
    if (!plain) return false;
    if (c == '.' && p[1] == '.') return false;    // no dot-dot anywhere
  }
  if (!slash || slash == rest) return false;      // need a tag...
  const char* file = slash + 1;                   // ...and a file

  static const char pre[] = "BambuHelper-";
  static const char suf[] = "-ota.bin";
  const size_t fl = strlen(file), pl = sizeof(pre) - 1, bl = strlen(board), sl = sizeof(suf) - 1;
  if (fl < pl + bl + 1 + sl) return false;
  if (memcmp(file, pre, pl) != 0) return false;
  if (memcmp(file + pl, board, bl) != 0 || file[pl + bl] != '-') return false;
  return memcmp(file + fl - sl, suf, sl) == 0;
}

// ---------------------------------------------------------------------------
//  HTML escaping for values placed in element text or a quoted attribute.
//  Returns the length written (excluding the terminator); output is always
//  terminated and never ends inside an entity.
// ---------------------------------------------------------------------------
inline size_t waHtmlEscape(const char* in, char* out, size_t outLen) {
  if (!out || outLen == 0) return 0;
  size_t w = 0;
  for (const char* p = in ? in : ""; *p; p++) {
    const char* rep = nullptr;
    switch (*p) {
      case '&':  rep = "&amp;";  break;
      case '<':  rep = "&lt;";   break;
      case '>':  rep = "&gt;";   break;
      case '"':  rep = "&quot;"; break;
      case '\'': rep = "&#39;";  break;
      default: break;
    }
    const size_t need = rep ? strlen(rep) : 1;
    if (w + need >= outLen) break;
    if (rep) memcpy(out + w, rep, need);
    else     out[w] = *p;
    w += need;
  }
  out[w] = '\0';
  return w;
}

// ---------------------------------------------------------------------------
//  Sign-in throttle: how long to refuse attempts after `fails` wrong passwords
//  in a row. The first few are free - people mistype.
// ---------------------------------------------------------------------------
inline uint32_t waLockoutSeconds(uint32_t fails) {
  if (fails < 5) return 0;
  const uint32_t step = fails - 5;
  if (step >= 5) return 300;
  const uint32_t s = 15u << step;                 // 15, 30, 60, 120, 240
  return s > 300 ? 300 : s;
}

// ---------------------------------------------------------------------------
//  Passwords
// ---------------------------------------------------------------------------
#define WA_PASSWORD_MIN  10
#define WA_PASSWORD_MAX  64

// A password the user picks: 10-64 printable ASCII characters.
inline bool waPasswordAcceptable(const char* pw) {
  if (!pw) return false;
  const size_t n = strlen(pw);
  if (n < WA_PASSWORD_MIN || n > WA_PASSWORD_MAX) return false;
  for (size_t i = 0; i < n; i++) {
    if (pw[i] < 0x20 || pw[i] > 0x7E) return false;
  }
  return true;
}

// The per-device password: 12 characters from 31 that cannot be mistaken for
// one another on a small screen (no i, l, o, 0, 1). About 59 bits.
#define WA_DEVICE_PASSWORD_LEN  12
static const char WA_DEVICE_ALPHABET[] = "abcdefghjkmnpqrstuvwxyz23456789";

inline bool waDevicePasswordValid(const char* pw) {
  if (!pw || strlen(pw) != WA_DEVICE_PASSWORD_LEN) return false;
  for (size_t i = 0; i < WA_DEVICE_PASSWORD_LEN; i++) {
    if (!pw[i] || !strchr(WA_DEVICE_ALPHABET, pw[i])) return false;
  }
  return true;
}

// Draw the password from a random-byte source. Rejection sampling keeps every
// character equally likely; a source that never yields a usable byte fails
// instead of looping forever or settling for a weak password.
inline bool waMakeDevicePassword(char* out, size_t outLen,
                                 void (*fill)(uint8_t* buf, size_t len)) {
  if (!out || outLen < WA_DEVICE_PASSWORD_LEN + 1 || !fill) return false;
  const size_t alphabet = sizeof(WA_DEVICE_ALPHABET) - 1;   // 31
  size_t n = 0;
  for (int round = 0; round < 16 && n < WA_DEVICE_PASSWORD_LEN; round++) {
    uint8_t buf[32];
    fill(buf, sizeof(buf));
    for (size_t i = 0; i < sizeof(buf) && n < WA_DEVICE_PASSWORD_LEN; i++) {
      const uint8_t v = buf[i] & 0x1F;
      if (v < alphabet) out[n++] = WA_DEVICE_ALPHABET[v];
    }
    memset(buf, 0, sizeof(buf));
  }
  if (n < WA_DEVICE_PASSWORD_LEN) { memset(out, 0, outLen); return false; }
  out[n] = '\0';
  return true;
}
