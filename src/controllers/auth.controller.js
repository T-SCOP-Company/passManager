const crypto = require("crypto");
const argon2 = require("argon2");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");
const User = require("../models/user.model");
const AuthChallenge = require("../models/authChallenge.model");
const { createEmailService } = require("../services/email.service");
const { audit } = require("../services/audit.service");

const OTP_TTL_MINUTES = 10;
const OTP_ATTEMPTS = 5;

function digestCode(challengeId, code, secret) {
  return crypto.createHmac("sha256", secret).update(`${challengeId}:${code}`).digest("hex");
}

function safeEqual(left, right) {
  const a = Buffer.from(left, "hex");
  const b = Buffer.from(right, "hex");
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function setSessionCookie(res, user, config) {
  const token = jwt.sign({ sub: user.id }, config.jwtSecret, { algorithm: "HS256", expiresIn: "8h" });
  res.cookie("session", token, {
    httpOnly: true,
    secure: config.production,
    sameSite: "strict",
    maxAge: 8 * 60 * 60 * 1000,
    path: "/",
  });
}

function authController(config) {
  const emailService = createEmailService(config);
  return {
    signin: async (req, res, next) => {
      try {
        const email = String(req.body.email || "").trim().toLowerCase();
        const user = await User.findOne({ email, status: "active" }).select("+passwordHash");
        if (!user || !(await argon2.verify(user.passwordHash, String(req.body.password || "")))) {
          await audit(req, { action: "auth.password_failed", result: "failure", metadata: { email } });
          return res.status(401).json({ success: false, error: "Incorrect email or password" });
        }

        req.user = user;
        await AuthChallenge.deleteMany({ userId: user._id, usedAt: null });
        const code = crypto.randomInt(10000000, 100000000).toString();
        const challenge = new AuthChallenge({
          userId: user._id,
          expiresAt: new Date(Date.now() + OTP_TTL_MINUTES * 60 * 1000),
          attemptsRemaining: OTP_ATTEMPTS,
          sendCount: 1,
          lastSentAt: new Date(),
          requestedIp: req.ip,
          code,
          codeDigest: "pending",
        });
        challenge.codeDigest = digestCode(challenge._id, code, config.jwtSecret);
        await challenge.save();
        try {
          await emailService.sendLoginCode({ to: user.email, code, expiresInMinutes: OTP_TTL_MINUTES });
        } catch (emailError) {
          await AuthChallenge.deleteOne({ _id: challenge._id });
          console.error("OTP email delivery failed", emailError.message);
          const authenticationFailed = emailError.responseCode === 535 || /invalid login|credentials invalid|username and password not accepted/i.test(emailError.message);
          return res.status(502).json({
            success: false,
            code: authenticationFailed ? "SMTP_AUTH_FAILED" : "OTP_DELIVERY_FAILED",
            error: authenticationFailed && !config.production
              ? "SMTP authentication failed. Update the sender mailbox password in .env and restart the application."
              : "Verification email could not be sent. Please try again or contact your administrator.",
          });
        }
        await audit(req, { action: "auth.otp_sent", result: "success", resourceType: "user", resourceId: user._id });
        res.json({ success: true, requiresOtp: true, challengeId: challenge.id, maskedEmail: user.email.replace(/(^.).*(@.*$)/, "$1***$2") });
      } catch (error) { next(error); }
    },

    verifyEmail: async (req, res, next) => {
      try {
        if (!mongoose.isValidObjectId(req.body.challengeId)) {
          return res.status(400).json({ success: false, error: "Verification code is expired or invalid" });
        }
        const challenge = await AuthChallenge.findOne({
          _id: req.body.challengeId,
          usedAt: null,
          expiresAt: { $gt: new Date() },
          attemptsRemaining: { $gt: 0 },
        }).select("+code +codeDigest");
        if (!challenge) return res.status(400).json({ success: false, error: "Verification code is expired or invalid" });

        const supplied = digestCode(challenge._id, String(req.body.code || ""), config.jwtSecret);
        if (!safeEqual(supplied, challenge.codeDigest)) {
          challenge.attemptsRemaining -= 1;
          await challenge.save();
          return res.status(400).json({ success: false, error: "Incorrect verification code" });
        }

        challenge.usedAt = new Date();
        challenge.code = undefined;
        await challenge.save();
        const user = await User.findOne({ _id: challenge.userId, status: "active" });
        if (!user) return res.status(401).json({ success: false, error: "User account is unavailable" });
        user.lastLoginAt = new Date();
        await user.save();
        req.user = user;
        setSessionCookie(res, user, config);
        await audit(req, { action: "auth.login", result: "success", resourceType: "user", resourceId: user._id });
        res.json({ success: true, user: user.toJSON() });
      } catch (error) { next(error); }
    },

    resendEmail: async (req, res, next) => {
      try {
        if (!mongoose.isValidObjectId(req.body.challengeId)) {
          return res.status(400).json({ success: false, error: "Verification request is invalid" });
        }
        const challenge = await AuthChallenge.findOne({
          _id: req.body.challengeId,
          usedAt: null,
          attemptsRemaining: { $gt: 0 },
        }).select("+code +codeDigest");
        if (!challenge || challenge.sendCount >= 4) {
          return res.status(429).json({ success: false, error: "Maximum resend limit reached. Sign in again to start a new request." });
        }
        if (Date.now() - challenge.lastSentAt.getTime() < 30 * 1000) {
          return res.status(429).json({ success: false, error: "Wait 30 seconds before requesting another code." });
        }
        const user = await User.findOne({ _id: challenge.userId, status: "active" });
        if (!user) return res.status(401).json({ success: false, error: "User account is unavailable" });
        const code = crypto.randomInt(10000000, 100000000).toString();
        challenge.code = code;
        challenge.codeDigest = digestCode(challenge._id, code, config.jwtSecret);
        challenge.expiresAt = new Date(Date.now() + OTP_TTL_MINUTES * 60 * 1000);
        challenge.attemptsRemaining = OTP_ATTEMPTS;
        challenge.sendCount += 1;
        challenge.lastSentAt = new Date();
        await challenge.save();
        try {
          await emailService.sendLoginCode({ to: user.email, code, expiresInMinutes: OTP_TTL_MINUTES });
        } catch (emailError) {
          await AuthChallenge.deleteOne({ _id: challenge._id });
          console.error("OTP resend failed", emailError.message);
          return res.status(502).json({ success: false, error: "A new verification code could not be sent" });
        }
        req.user = user;
        await audit(req, { action: "auth.otp_resent", result: "success", resourceType: "user", resourceId: user._id });
        res.json({ success: true, challengeId: challenge.id, maskedEmail: user.email.replace(/(^.).*(@.*$)/, "$1***$2") });
      } catch (error) { next(error); }
    },

    signout: async (req, res) => {
      res.clearCookie("session", { path: "/" });
      await audit(req, { action: "auth.logout", result: "success" });
      res.json({ success: true });
    },
    me: (req, res) => res.json({ success: true, user: req.user }),
  };
}

module.exports = { authController };
