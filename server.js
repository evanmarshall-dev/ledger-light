// IMPORTS
const dotenv = require("dotenv");
dotenv.config();
const path = require("path");
const express = require("express");
const mongoose = require("mongoose");
const methodOverride = require("method-override");
const session = require("express-session");
const helmet = require("helmet");
const morgan = require("morgan");
const MongoStore = require("connect-mongo");

// ROUTE IMPORTS
const indexRoutes = require("./routes/index");
const transactionsRoutes = require("./routes/transactions");
const authRoutes = require("./routes/auth");

// CSRF middleware (in-repo)
const { csrfMiddleware } = require("./middleware/csrf");

// VARIABLES / APP INITIALIZATION
const ledgerApp = express();
const config = require("./config");
const port = config.port;
// When behind a proxy (Heroku, etc.) we must trust the proxy so that
// secure cookies (cookie.secure) and req.protocol (for req.secure) work.
// This is required when `cookie.secure` is true and TLS is terminated at the
// platform load balancer / proxy. Only enable in production.
if (config.isProduction) {
  ledgerApp.set("trust proxy", 1);
}

// ------------------
// MIDDLEWARE
// ------------------
// Serve static assets from /public (CSS, client JS, images). Keep early so static
// requests bypass most middleware and are fast.
ledgerApp.use(express.static(path.join(__dirname, "public")));

// Views configuration for server-rendered templates
ledgerApp.set("views", path.join(__dirname, "views"));
ledgerApp.set("view engine", "ejs");

// BODY PARSING
// ------------------
// - urlencoded: form submissions
// - json: API clients or fetch() from the browser
ledgerApp.use(express.urlencoded({ extended: true }));
ledgerApp.use(express.json());

// Support forms that need PUT/DELETE via ?_method=PUT
ledgerApp.use(methodOverride("_method"));

// Helmet base headers (other policies applied below)
ledgerApp.use(helmet());

// HTTP request logging (dev friendly). Replace or configure for production.
ledgerApp.use(morgan("dev"));

// Session middleware with MongoDB-backed store (persist sessions across restarts)
ledgerApp.use(
  session({
    secret: config.sessionSecret,
    resave: false,
    saveUninitialized: false,
    // MongoDB session persistence
    store: MongoStore.create({ mongoUrl: config.mongoUri }),
    // Session secure cookie settings
    cookie: {
      httpOnly: true,
      secure: config.isProduction,
      // stricter sameSite to reduce CSRF risk for this app
      sameSite: "strict",
      maxAge: 24 * 60 * 60 * 1000, // 1 day
    },
  })
);

// DEFAULT LOCALS FOR TEMPLATES
ledgerApp.use((req, res, next) => {
  res.locals.siteTitle = config.siteTitle;
  // modern common practice: Page Title | Site Name
  res.locals.titleTemplate = config.titleTemplate;
  // expose session user if you plan auth later
  res.locals.currentUser =
    req.session && req.session.user ? req.session.user : null;
  next();
});
// Flash messages (simple session-backed implementation)
const { flashMiddleware } = require("./middleware/flash");
ledgerApp.use(flashMiddleware);
// Apply a restrictive Content Security Policy (adjust if you load external assets)
ledgerApp.use(
  helmet.contentSecurityPolicy({
    directives: {
      // Keep a restrictive default and explicitly allow known trusted external
      // hosts that the app may use for fonts or CDNs. Adjust as needed.
      defaultSrc: ["'self'"],
      // Allow same-origin scripts and common CDNs used for libraries or widgets
      scriptSrc: ["'self'", "https://cdn.jsdelivr.net", "https://unpkg.com"],
      // Allow styles from same-origin, secure (https) origins and Google Fonts.
      // Note: avoid 'unsafe-inline' where possible — only add if your templates
      // inject inline styles that can't be removed.
      styleSrc: [
        "'self'",
        "https://fonts.googleapis.com",
        "https://cdn.jsdelivr.net",
        "https://unpkg.com",
        "https:",
      ],
      // Allow font files from Google Fonts and other trusted hosts.
      fontSrc: [
        "'self'",
        "https://fonts.gstatic.com",
        "https://fonts.googleapis.com",
        "https:",
      ],
      // Images: same-origin and data URIs (for inline images)
      imgSrc: ["'self'", "data:", "https:"],
      // API / fetch endpoints the front-end may talk to
      connectSrc: ["'self'", "https:"],
    },
  })
);

// CSRF protection (simple in-repo implementation)
ledgerApp.use(csrfMiddleware);

// ROUTES
ledgerApp.use("/", indexRoutes);
ledgerApp.use("/auth", authRoutes);
ledgerApp.use("/transactions", transactionsRoutes);

// DATABASE & SERVER
mongoose
  .connect(config.mongoUri)
  .then(() => {
    console.log("MongoDB connected");
    ledgerApp.listen(port, () => {
      console.log(`Server is running on port ${port}`);
    });
  })
  .catch((err) => {
    console.error("MongoDB connection error:", err);
    process.exit(1);
  });

// ERROR HANDLER
ledgerApp.use((err, req, res, next) => {
  console.error("Unhandled error:", err);
  if (res.headersSent) return next(err);
  res.status(500).send("Internal Server Error");
});
