// =============================================================================
//  web_auth.h - sign-in for the settings portal.
//
//  Nothing the portal can do is reachable without a session: every route is
//  registered through webAuthWrap(), and the two upload callbacks (which the
//  web server runs while the body is still arriving, before any route handler)
//  ask webAuthAllowed() themselves.
//
//  A session is a random cookie handed out by POST /login in exchange for the
//  portal password - the per-device password shown on the screen, or the one
//  the user replaced it with. Requests must also come from the portal's own
//  pages (Origin / Referer agree with Host), so another website open in the
//  same browser cannot ride a signed-in session.
//
//  The portal is plain HTTP. This keeps other devices and other websites out;
//  it does not protect against someone who can read or alter the traffic
//  between the browser and the device.
// =============================================================================
#pragma once

#include <WebServer.h>

// Register /login, /logout and /auth/password and tell the server which
// request headers to keep. Call once, before server.begin(). `extraHeaders`
// are header names other handlers need collected (collectHeaders() replaces
// the whole list, so there can only be one call).
void webAuthBegin(const char* const* extraHeaders, size_t extraCount);

// True when the current request carries a live session and comes from the
// portal itself. Sends nothing.
bool webAuthAllowed();

// Same test, but answers the request itself when it fails: a redirect to the
// sign-in page for the portal's front page, 401/403 for everything else.
bool webAuthGuard();

// Wrap a route handler so it only runs for an allowed request.
WebServer::THandlerFunction webAuthWrap(void (*handler)());

// Housekeeping, called from the main loop: retires idle sessions and an
// expired sign-in throttle.
void webAuthTick();
