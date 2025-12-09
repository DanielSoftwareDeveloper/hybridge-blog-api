const express = require("express");
const router = express.Router();
const passport = require("passport");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const db = require("../models");

// SIGNUP
router.post("/signup", async (req, res) => {
  try {
    const { name, email, password } = req.body;
    const hash = await bcrypt.hash(password, 10);

    const user = await db.User.create({
      name,
      email,
      password: hash,
    });

    res.status(201).json({
      id: user.id,
      email: user.email,
    });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

// LOGIN
router.post(
  "/login",
  passport.authenticate("local", { session: false }),
  (req, res) => {
    const payload = { id: req.user.id };

    const token = jwt.sign(payload, process.env.JWT_SECRET, {
      expiresIn: "1h",
    });

    res.json({
      token,
      token_type: "Bearer",
    });
  }
);

module.exports = router;
