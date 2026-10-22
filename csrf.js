// server/routes/csrf.js
// Member 2: Faisal Imran - CSRF Module Backend
// Session creation and state-changing (change-email) demonstration endpoint.

const express = require("express");
const crypto = require("crypto");

const router = express.Router();

const CLIENT_URL = process.env.CLIENT_URL || "http://localhost:5173";

function isVulnerable(mode) {
  return mode === "vulnerable" && process.env.NODE_ENV !== "production";
}

function getCookie(req, name) {
  const cookies = (req.headers.cookie || "").split(";");

  for (const cookie of cookies) {
    const separator = cookie.indexOf("=");
    if (separator === -1) continue;

    const key = cookie.slice(0, separator).trim();
    const value = cookie.slice(separator + 1).trim();

    if (key === name) {
      try {
        return decodeURIComponent(value);
      } catch {
        return null;
      }
    }
  }

  return null;
}

// CSRF training sessions
// Demonstration only; these are not production authentication sessions.
const csrfSessions = new Map();

router.get("/lab/csrf/session", (req, res) => {
  const sessionId = crypto.randomBytes(24).toString("hex");
  const csrfToken = crypto.randomBytes(32).toString("hex");

  csrfSessions.set(sessionId, {
    csrfToken,
    email: "student@example.test"
  });

  res.cookie("lab_session", sessionId, {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    path: "/",
    maxAge: 15 * 60 * 1000
  });

  res.json({
    message: "Lab session created",
    email: "student@example.test",
    csrfToken
  });
});

// State-changing CSRF demonstration endpoint
router.post("/lab/csrf/change-email", (req, res) => {
  const requestedMode = req.query.mode || req.body.mode;

  // Safe is the default. Only an explicit vulnerable mode bypasses
  // token validation, and that mode is disabled in production.
  const vulnerable = isVulnerable(requestedMode);

  console.log("CSRF route reached");
  console.log("Requested mode:", requestedMode);
  console.log("Vulnerable mode:", vulnerable);

  const sessionId = getCookie(req, "lab_session");
  const session = csrfSessions.get(sessionId);

  if (!session) {
    return res.status(401).json({
      error: "Create a lab session first."
    });
  }

  const email = String(req.body.email || "").trim();

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({
      error: "Invalid email address"
    });
  }

  if (!vulnerable) {
    const origin = req.get("Origin");
    const suppliedToken = req.get("X-CSRF-Token");

    console.log("Safe validation reached");
    console.log("Origin matches:", origin === CLIENT_URL);
    console.log("Token received:", Boolean(suppliedToken));
    console.log(
      "Token matches session:",
      suppliedToken === session.csrfToken
    );

    if (origin !== CLIENT_URL) {
      return res.status(403).json({
        error: "Blocked: request origin is not trusted."
      });
    }

    if (
      typeof suppliedToken !== "string" ||
      suppliedToken.length === 0 ||
      suppliedToken !== session.csrfToken
    ) {
      return res.status(403).json({
        error: "Blocked: CSRF token is missing or invalid."
      });
    }
  }

  // State changes only after Safe mode validation passes.
  session.email = email;

  return res.json({
    mode: vulnerable ? "vulnerable" : "safe",
    message: "Email updated successfully",
    email: session.email
  });
});

module.exports = router;
