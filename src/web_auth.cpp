#include "web_auth.h"
#include "web_auth_logic.h"
#include "web_template.h"   // the shared WebServer instance
#include "settings.h"
#include "esp_system.h"     // esp_fill_random
#include <new>

// ---------------------------------------------------------------------------
//  Sessions
//
//  RAM only: a reboot signs everybody out. Four is enough for a household and
//  keeps the table a fixed size; a fifth sign-in replaces the one idle longest.
// ---------------------------------------------------------------------------
#define SESSION_COUNT    4
#define SESSION_TOKEN_LEN 16
#define SESSION_IDLE_MS  (30UL * 60UL * 1000UL)
static const char SESSION_COOKIE[] = "bh_sid";

struct Session {
  uint8_t  token[SESSION_TOKEN_LEN];
  uint32_t seenMs;
  bool     live;
};
static Session s_sessions[SESSION_COUNT];

static void endSession(Session& s) {
  memset(s.token, 0, sizeof(s.token));
  s.live = false;
}

// Index of the session the request's cookie names, or -1.
static int sessionFromRequest() {
  String cookie = server.header("Cookie");
  char hex[SESSION_TOKEN_LEN * 2 + 1];
  uint8_t token[SESSION_TOKEN_LEN];
  if (!waCookieValue(cookie.c_str(), SESSION_COOKIE, hex, sizeof(hex))) return -1;
  if (!waHexToBytes(hex, token, sizeof(token))) return -1;

  const uint32_t now = millis();
  int found = -1;
  for (int i = 0; i < SESSION_COUNT; i++) {
    Session& s = s_sessions[i];
    if (!s.live) continue;
    if (now - s.seenMs > SESSION_IDLE_MS) { endSession(s); continue; }
    // No early exit: every live token is compared in full.
    if (waCtEqual(token, s.token, sizeof(token))) found = i;
  }
  if (found >= 0) s_sessions[found].seenMs = now;
  return found;
}

// Start a session and return its cookie value in `hex`.
static void startSession(char* hex) {
  const uint32_t now = millis();
  int slot = -1;
  uint32_t oldest = 0;
  for (int i = 0; i < SESSION_COUNT; i++) {
    if (!s_sessions[i].live) { slot = i; break; }
    const uint32_t idle = now - s_sessions[i].seenMs;
    if (slot < 0 || idle > oldest) { slot = i; oldest = idle; }
  }
  Session& s = s_sessions[slot];
  esp_fill_random(s.token, sizeof(s.token));   // radio is up: true random
  s.seenMs = now;
  s.live = true;
  waBytesToHex(s.token, sizeof(s.token), hex);
}

// ---------------------------------------------------------------------------
//  Sign-in throttle
//
//  One counter for the whole device rather than per address: addresses on a
//  LAN are free to change, so a per-address limit limits nobody.
// ---------------------------------------------------------------------------
static uint32_t s_fails = 0;
static uint32_t s_lockStartMs = 0;
static uint32_t s_lockSecs = 0;

static uint32_t lockRemainingSecs() {
  if (s_lockSecs == 0) return 0;
  const uint32_t elapsed = (millis() - s_lockStartMs) / 1000UL;
  if (elapsed >= s_lockSecs) { s_lockSecs = 0; return 0; }
  return s_lockSecs - elapsed;
}

static void noteFailure() {
  if (s_fails < 1000) s_fails++;
  s_lockSecs = waLockoutSeconds(s_fails);
  s_lockStartMs = millis();
}

void webAuthTick() {
  static uint32_t lastMs = 0;
  const uint32_t now = millis();
  if (now - lastMs < 10000UL) return;
  lastMs = now;
  for (int i = 0; i < SESSION_COUNT; i++) {
    Session& s = s_sessions[i];
    if (s.live && now - s.seenMs > SESSION_IDLE_MS) endSession(s);
  }
  lockRemainingSecs();   // clears the throttle once it has run out
}

// ---------------------------------------------------------------------------
//  Request checks
// ---------------------------------------------------------------------------
static bool sameOrigin() {
  // The collected "Host" value, not server.hostHeader(): that one is not
  // cleared between requests.
  String host = server.header("Host");
  String origin = server.header("Origin");
  String referer = server.header("Referer");
  host.trim(); origin.trim(); referer.trim();
  return waSameOrigin(origin.c_str(), referer.c_str(), host.c_str());
}

bool webAuthAllowed() {
  return sameOrigin() && sessionFromRequest() >= 0;
}

bool webAuthGuard() {
  // Cache-Control goes on the refusals only: a handler that runs sets its own,
  // and a second header here would contradict it.
  if (!sameOrigin()) {
    server.sendHeader("Cache-Control", "no-store");
    server.send(403, "text/plain", "Cross-site request refused");
    return false;
  }
  if (sessionFromRequest() < 0) {
    server.sendHeader("Cache-Control", "no-store");
    if (server.method() == HTTP_GET && server.uri() == "/") {
      server.sendHeader("Location", "/login");
      server.send(302, "text/plain", "");
    } else {
      server.send(401, "application/json",
                  "{\"status\":\"error\",\"error\":\"Sign in required\",\"message\":\"Sign in required\"}");
    }
    return false;
  }
  return true;
}

WebServer::THandlerFunction webAuthWrap(void (*handler)()) {
  return [handler]() { if (webAuthGuard()) handler(); };
}

// ---------------------------------------------------------------------------
//  Sign-in page. Self-contained (no script, no external asset) so it renders
//  in a phone's captive-portal sheet, and so nothing else has to be reachable
//  without a session.
// ---------------------------------------------------------------------------
static const char LOGIN_HEAD[] PROGMEM = R"rawliteral(<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>BambuHelper - Sign in</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0D1117;color:#E6EDF3;padding:16px;max-width:420px;margin:0 auto}
h1{color:#58A6FF;font-size:22px;margin-bottom:6px}
.sub{color:#8B949E;font-size:13px;margin-bottom:20px}
.card{background:#161B22;border:1px solid #30363D;border-radius:8px;padding:16px}
label{display:block;color:#8B949E;font-size:13px;margin-bottom:4px}
input{width:100%;padding:8px 10px;border:1px solid #30363D;border-radius:6px;background:#0D1117;color:#E6EDF3;font-size:14px;outline:none}
input:focus{border-color:#58A6FF}
button{display:block;width:100%;padding:12px;border:none;border-radius:6px;font-size:15px;font-weight:600;cursor:pointer;margin-top:16px;background:#238636;color:#fff}
.err{color:#F85149;font-size:13px;margin-bottom:12px}
.note{color:#8B949E;font-size:12px;line-height:1.45;margin-top:14px}
</style></head><body>
<h1>BambuHelper</h1>
<p class="sub">Sign in to change settings</p>
<div class="card">
)rawliteral";

static const char LOGIN_TAIL[] PROGMEM = R"rawliteral(
<form method="POST" action="/login">
<label for="password">Password</label>
<input type="password" id="password" name="password" maxlength="64" autocomplete="current-password" autofocus required>
<button type="submit">Sign in</button>
</form>
<p class="note">Unless you changed it, the password is the one the device shows on its own screen: under <em>Password</em> on the WiFi Setup screen, and under <em>Web password</em> after it joins your network. It is the same password as the setup hotspot's.</p>
</div></body></html>
)rawliteral";

static void sendLoginPage(int code, const char* error) {
  String page;
  page.reserve(sizeof(LOGIN_HEAD) + sizeof(LOGIN_TAIL) + 96);
  page += FPSTR(LOGIN_HEAD);
  if (error && error[0]) {            // fixed text only - never request data
    page += "<p class=\"err\" role=\"alert\">";
    page += error;
    page += "</p>";
  }
  page += FPSTR(LOGIN_TAIL);
  server.sendHeader("Cache-Control", "no-store");
  server.sendHeader("X-Frame-Options", "DENY");
  server.send(code, "text/html", page);
}

static void handleLoginPage() {
  if (sameOrigin() && sessionFromRequest() >= 0) {
    server.sendHeader("Location", "/");
    server.send(302, "text/plain", "");
    return;
  }
  sendLoginPage(200, nullptr);
}

static void handleLoginSubmit() {
  if (!sameOrigin()) {
    server.sendHeader("Cache-Control", "no-store");
    server.send(403, "text/plain", "Cross-site request refused");
    return;
  }
  const uint32_t wait = lockRemainingSecs();
  if (wait > 0) {
    char msg[72];
    snprintf(msg, sizeof(msg), "Too many wrong passwords. Try again in %u s.", (unsigned)wait);
    sendLoginPage(429, msg);
    return;
  }

  String password = server.arg("password");
  const bool ok = checkWebPassword(password.c_str());
  // Overwrite our copy; the server's own argument buffer lives until the next
  // request and cannot be reached from here.
  for (size_t i = 0; i < password.length(); i++) password.setCharAt(i, '\0');
  if (!ok) {
    noteFailure();
    sendLoginPage(401, "Wrong password.");
    return;
  }

  s_fails = 0;
  s_lockSecs = 0;
  markWebLoginSeen();

  char hex[SESSION_TOKEN_LEN * 2 + 1];
  startSession(hex);
  String cookie = String(SESSION_COOKIE) + "=" + hex + "; Path=/; HttpOnly; SameSite=Strict";
  server.sendHeader("Set-Cookie", cookie);
  server.sendHeader("Cache-Control", "no-store");
  server.sendHeader("Location", "/");
  server.send(303, "text/plain", "");
}

static void handleLogout() {
  const int i = sessionFromRequest();
  if (i >= 0) endSession(s_sessions[i]);
  server.sendHeader("Set-Cookie",
                    String(SESSION_COOKIE) + "=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict");
  server.send(200, "application/json", "{\"status\":\"ok\"}");
}

// Replace the portal password. Needs the current one even with a session, so
// a browser left signed in cannot be used to lock the owner out, and wrong
// guesses count toward the same throttle as the sign-in page.
static void handlePasswordChange() {
  const uint32_t wait = lockRemainingSecs();
  if (wait > 0) {
    server.send(429, "application/json",
                "{\"status\":\"error\",\"message\":\"Too many wrong passwords. Wait a few minutes and try again.\"}");
    return;
  }
  String current = server.arg("cur");
  String next = server.arg("new");
  if (!checkWebPassword(current.c_str())) {
    noteFailure();
    server.send(403, "application/json",
                "{\"status\":\"error\",\"message\":\"The current password is wrong.\"}");
    return;
  }
  if (!waPasswordAcceptable(next.c_str())) {
    server.send(400, "application/json",
                "{\"status\":\"error\",\"message\":\"Use 10 to 64 characters: letters, digits, spaces and common symbols.\"}");
    return;
  }
  if (!setWebPassword(next.c_str())) {
    server.send(500, "application/json",
                "{\"status\":\"error\",\"message\":\"The password could not be stored - settings storage is full.\"}");
    return;
  }
  // Everyone else holding a session got it with the old password.
  const int me = sessionFromRequest();
  for (int i = 0; i < SESSION_COUNT; i++) {
    if (i != me) endSession(s_sessions[i]);
  }
  server.send(200, "application/json", "{\"status\":\"ok\"}");
}

void webAuthBegin(const char* const* extraHeaders, size_t extraCount) {
  static const char* const own[] = { "Cookie", "Origin", "Referer", "Host" };
  const size_t ownCount = sizeof(own) / sizeof(own[0]);
  const char** keys = new (std::nothrow) const char*[ownCount + extraCount];
  if (keys) {
    for (size_t i = 0; i < ownCount; i++) keys[i] = own[i];
    for (size_t i = 0; i < extraCount; i++) keys[ownCount + i] = extraHeaders[i];
    server.collectHeaders(keys, ownCount + extraCount);   // copies the names
    delete[] keys;
  }
  // Without the Cookie header collected no request can ever present a session,
  // so an allocation failure above leaves the portal closed, not open.

  ensureDevicePassword();   // normally already done by the WiFi start-up

  server.on("/login", HTTP_GET, handleLoginPage);
  server.on("/login", HTTP_POST, handleLoginSubmit);
  server.on("/logout", HTTP_POST, webAuthWrap(handleLogout));
  server.on("/auth/password", HTTP_POST, webAuthWrap(handlePasswordChange));
}
