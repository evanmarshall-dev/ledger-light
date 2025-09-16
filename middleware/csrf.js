const crypto = require("crypto");

// Simple CSRF middleware that stores a single token per session.
// - Generates token for safe methods and exposes it as res.locals.csrfToken
// - Validates token for state-changing methods (POST/PUT/PATCH/DELETE)
// Accepts token from req.body._csrf or header 'x-csrf-token'.

function ensureCsrfToken(req) {
  if (!req.session) return null;
  if (!req.session.csrfToken) {
    req.session.csrfToken = crypto.randomBytes(24).toString("hex");
  }
  return req.session.csrfToken;
}

exports.csrfMiddleware = (req, res, next) => {
  // Skip CSRF for XHR/JSON requests that present an Authorization header
  const wantsJSON =
    req.headers.accept && req.headers.accept.indexOf("application/json") !== -1;

  // Provide token for templates on GET/HEAD
  if (
    req.method === "GET" ||
    req.method === "HEAD" ||
    req.method === "OPTIONS"
  ) {
    const token = ensureCsrfToken(req);
    if (token) res.locals.csrfToken = token;
    return next();
  }

  // For state-changing methods, validate token unless request is JSON API (we allow header-based tokens)
  if (
    req.method === "POST" ||
    req.method === "PUT" ||
    req.method === "PATCH" ||
    req.method === "DELETE"
  ) {
    const sessionToken = req.session && req.session.csrfToken;
    const sentToken = (req.body && req.body._csrf) || req.get("x-csrf-token");
    if (!sessionToken)
      return res.status(403).send("CSRF token missing in session");
    if (!sentToken) return res.status(403).send("CSRF token missing");
    if (sentToken !== sessionToken)
      return res.status(403).send("Invalid CSRF token");
    // valid
    return next();
  }

  // default
  next();
};
