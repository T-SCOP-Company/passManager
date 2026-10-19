const express = require("express");
const rateLimit = require("express-rate-limit");
const { authController } = require("../controllers/auth.controller");
const users = require("../controllers/user.controller");
const platforms = require("../controllers/platform.controller");
const vault = require("../controllers/vault.controller");
const usefulLinks = require("../controllers/usefulLink.controller");
const { authMiddleware, requireRole } = require("../middleware/auth");

function createRoutes(config) {
  const router = express.Router();
  const auth = authMiddleware(config);
  const authActions = authController(config);
  const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 10, standardHeaders: "draft-8" });
  const otpLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 10, standardHeaders: "draft-8" });
  const resendLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 4, standardHeaders: "draft-8" });

  router.post("/auth/signin", loginLimiter, authActions.signin);
  router.post("/auth/verify-email", otpLimiter, authActions.verifyEmail);
  router.post("/auth/resend-email", resendLimiter, authActions.resendEmail);
  router.post("/auth/signout", auth, authActions.signout);
  router.get("/auth/me", auth, authActions.me);
  router.get("/users", auth, requireRole("admin", "superAdmin"), users.list);
  router.get("/users/directory", auth, users.directory);
  router.post("/users", auth, requireRole("admin", "superAdmin"), users.create);
  router.patch("/users/:id", auth, requireRole("admin", "superAdmin"), users.update);
  router.delete("/users/:id", auth, requireRole("admin", "superAdmin"), users.remove);
  router.get("/platforms", auth, platforms.list);
  router.post("/platforms", auth, requireRole("admin", "superAdmin"), platforms.create);
  router.patch("/platforms/:id", auth, requireRole("admin", "superAdmin"), platforms.update);
  router.delete("/platforms/:id", auth, requireRole("admin", "superAdmin"), platforms.remove);
  router.get("/vault", auth, vault.list);
  router.get("/vault-access", auth, vault.accessMatrix);
  router.post("/vault", auth, vault.create);
  router.patch("/vault/:id", auth, vault.update);
  router.delete("/vault/:id", auth, vault.remove);
  router.post("/vault/:id/reveal", auth, vault.reveal);
  router.put("/vault/:id/grants", auth, vault.grant);
  router.delete("/vault/:id/grants/:userId", auth, vault.revokeGrant);
  router.get("/useful-links", auth, usefulLinks.list);
  router.post("/useful-links", auth, requireRole("admin", "superAdmin"), usefulLinks.create);
  router.patch("/useful-links/:id", auth, requireRole("admin", "superAdmin"), usefulLinks.update);
  router.delete("/useful-links/:id", auth, requireRole("admin", "superAdmin"), usefulLinks.remove);
  return router;
}

module.exports = { createRoutes };
