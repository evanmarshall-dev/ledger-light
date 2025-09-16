// Minimal auth helpers for routes. This file does not implement login or
// registration — it assumes some authentication flow will populate
// req.session.user = { _id, email, ... } on successful sign-in.

exports.ensureAuthenticated = (req, res, next) => {
  if (req.session && req.session.user) return next();
  // Redirect to the mounted auth login route and include the originally
  // requested URL so we can return the user after sign-in.
  const nextUrl = req.originalUrl || "/";
  res.redirect(`/auth/login?next=${encodeURIComponent(nextUrl)}`);
};

// Helper to attach user into session after successful auth
// Use this after regenerating the session to prevent fixation attacks.
exports.login = (req, user) => {
  req.session.user = {
    _id: user._id.toString(),
    email: user.email,
    username: user.username || null,
  };
};

exports.logout = (req) => {
  if (req.session) {
    req.session.destroy(() => {});
  }
};
