import { Router } from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import User from "../models/User.js";
import { requireAuth } from "../middleware/auth.js";

const router = Router();

function signToken(userId) {
  return jwt.sign({ userId }, process.env.JWT_SECRET, { expiresIn: "30d" });
}
function genRecoveryCode() {
  return crypto.randomBytes(10).toString("hex").toUpperCase().match(/.{1,4}/g).join("-");
}

// Create the account. Requires ADMIN_SIGNUP_CODE (set by you on the server) —
// this is what stops anyone with the app URL from just signing themselves
// up. Only share that code with people you specifically want to have
// access; change it on Render anytime to cut off future signups (existing
// accounts are unaffected). Binds the device that signs up as the allowed
// device for that account.
router.post("/signup", async (req, res) => {
  try {
    const { username, password, deviceToken, deviceLabel, adminCode } = req.body || {};
    if (!username || !password || !deviceToken) {
      return res.status(400).json({ error: "Username, password, and device token are required." });
    }
    if (!process.env.ADMIN_SIGNUP_CODE) {
      return res.status(500).json({ error: "Signups are not configured on this server yet (missing ADMIN_SIGNUP_CODE)." });
    }
    if (!adminCode || adminCode !== process.env.ADMIN_SIGNUP_CODE) {
      return res.status(403).json({ error: "Invalid access code. Ask the administrator for the current signup code." });
    }
    if (password.length < 6) {
      return res.status(400).json({ error: "Password must be at least 6 characters." });
    }
    const existing = await User.findOne({ username: username.toLowerCase() });
    if (existing) return res.status(409).json({ error: "That username is already taken." });

    const passwordHash = await bcrypt.hash(password, 12);
    const recoveryCode = genRecoveryCode();
    const recoveryCodeHash = await bcrypt.hash(recoveryCode, 12);

    const user = await User.create({
      username: username.toLowerCase(),
      passwordHash,
      recoveryCodeHash,
      boundDeviceToken: deviceToken,
      boundDeviceLabel: deviceLabel || null,
    });

    const token = signToken(user._id.toString());
    res.json({ token, recoveryCode });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Signup failed. Please try again." });
  }
});

// Login. Enforces the device lock: if this account is already bound to a
// different device token, the login is rejected outright, regardless of
// whether the password is correct.
router.post("/login", async (req, res) => {
  try {
    const { username, password, deviceToken } = req.body || {};
    if (!username || !password || !deviceToken) {
      return res.status(400).json({ error: "Username, password, and device token are required." });
    }
    const user = await User.findOne({ username: username.toLowerCase() });
    if (!user) return res.status(401).json({ error: "Incorrect username or password." });

    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.status(401).json({ error: "Incorrect username or password." });

    if (!user.boundDeviceToken) {
      // No device bound yet (shouldn't normally happen post-signup, but
      // handle gracefully) — bind this one.
      user.boundDeviceToken = deviceToken;
      await user.save();
    } else if (user.boundDeviceToken !== deviceToken) {
      return res.status(403).json({
        error: "This account is already registered to another device. Use 'Reset device access' with your recovery code to move it here.",
        code: "DEVICE_LOCKED",
      });
    }

    const token = signToken(user._id.toString());
    res.json({ token });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Login failed. Please try again." });
  }
});

// Change password (requires being logged in on the already-bound device).
router.post("/change-password", requireAuth, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body || {};
    if (!currentPassword || !newPassword) {
      return res.status(400).json({ error: "Current and new password are required." });
    }
    if (newPassword.length < 6) {
      return res.status(400).json({ error: "New password must be at least 6 characters." });
    }
    const user = await User.findById(req.userId);
    if (!user) return res.status(404).json({ error: "Account not found." });

    const ok = await bcrypt.compare(currentPassword, user.passwordHash);
    if (!ok) return res.status(401).json({ error: "Current password is incorrect." });

    user.passwordHash = await bcrypt.hash(newPassword, 12);
    await user.save();
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Could not change password. Please try again." });
  }
});

// Recovery flow — covers both "forgot password" and "reset device" cases.
// Requires the recovery code (proves account ownership without needing the
// current device or, optionally, the current password). Always rebinds the
// account to whatever device token is presented here, and issues a fresh
// recovery code (the old one is single-use).
router.post("/recover", async (req, res) => {
  try {
    const { username, recoveryCode, newPassword, deviceToken, deviceLabel } = req.body || {};
    if (!username || !recoveryCode || !deviceToken) {
      return res.status(400).json({ error: "Username, recovery code, and device token are required." });
    }
    const user = await User.findOne({ username: username.toLowerCase() });
    if (!user) return res.status(401).json({ error: "Incorrect username or recovery code." });

    const ok = await bcrypt.compare(recoveryCode.trim(), user.recoveryCodeHash);
    if (!ok) return res.status(401).json({ error: "Incorrect username or recovery code." });

    if (newPassword) {
      if (newPassword.length < 6) return res.status(400).json({ error: "New password must be at least 6 characters." });
      user.passwordHash = await bcrypt.hash(newPassword, 12);
    }
    user.boundDeviceToken = deviceToken;
    user.boundDeviceLabel = deviceLabel || null;

    const newRecoveryCode = genRecoveryCode();
    user.recoveryCodeHash = await bcrypt.hash(newRecoveryCode, 12);
    await user.save();

    const token = signToken(user._id.toString());
    res.json({ token, recoveryCode: newRecoveryCode });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Recovery failed. Please try again." });
  }
});

// Simple check used by the frontend to confirm a stored session is still valid.
router.get("/me", requireAuth, async (req, res) => {
  const user = await User.findById(req.userId).select("username boundDeviceLabel createdAt");
  if (!user) return res.status(404).json({ error: "Account not found." });
  res.json({ username: user.username, deviceLabel: user.boundDeviceLabel, createdAt: user.createdAt });
});

export default router;
