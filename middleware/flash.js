// Simple flash message middleware using session
// - set flash by assigning req.session.flash = { success: [...], error: [...] }
// - middleware moves it to res.locals.flash and clears it from session

exports.flashMiddleware = (req, res, next) => {
  if (req.session && req.session.flash) {
    res.locals.flash = req.session.flash;
    delete req.session.flash;
  } else {
    res.locals.flash = {};
  }
  // helper to push a flash message in controllers
  req.flash = (type, msg) => {
    if (!req.session) return;
    req.session.flash = req.session.flash || {};
    req.session.flash[type] = req.session.flash[type] || [];
    req.session.flash[type].push(msg);
  };
  next();
};
