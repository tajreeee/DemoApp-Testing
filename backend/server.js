// server.js
const express = require("express");
const mysql = require("mysql2");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");
const { google } = require("googleapis");
const cors = require("cors");
const path = require("path");
require("dotenv").config();

const app = express();
app.use(express.json());
app.use(cors());

// --------------------- DATABASE ---------------------
const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

db.connect(err => {
  if (err) throw err;
  console.log("MySQL Database Connected");
});

// --------------------- GOOGLE OAUTH2 ---------------------
const OAuth2 = google.auth.OAuth2;
const oauth2Client = new OAuth2(
  process.env.CLIENT_ID,
  process.env.CLIENT_SECRET,
  "https://developers.google.com/oauthplayground"
);

oauth2Client.setCredentials({
  refresh_token: process.env.REFRESH_TOKEN,
});

// --------------------- EMAIL SENDER ---------------------
async function sendVerificationEmail(email, token) {
  const accessToken = await oauth2Client.getAccessToken();

  const transport = nodemailer.createTransport({
    service: "gmail",
    auth: {
      type: "OAuth2",
      user: process.env.EMAIL_USER,
      clientId: process.env.CLIENT_ID,
      clientSecret: process.env.CLIENT_SECRET,
      refreshToken: process.env.REFRESH_TOKEN,
      accessToken: accessToken,
    },
  });

  // const verifyURL = `${process.env.CLIENT_URL}/verify.html?token=${token}`;
     const verifyURL = `http://localhost:5000/verify?token=${token}`;

  const mailOptions = {
    from: `TechWeave <${process.env.EMAIL_USER}>`,
    to: email,
    subject: "Verify Your Email - TechWeave",
    html: `
      <h2>Email Verification</h2>
      <p>Click the link below to verify your email:</p>
      <a href="${verifyURL}">Verify Email</a>
    `,
  };

  await transport.sendMail(mailOptions);
}

// --------------------- SERVE FRONTEND ---------------------
app.use(express.static(path.join(__dirname, "../frontend")));


// --------------------- SIGNUP ---------------------
app.post("/signup", async (req, res) => {
  const { username, email, password } = req.body;

  db.query("SELECT * FROM users WHERE email=?", [email], async (err, result) => {
    if (err) return res.status(500).json({ message: "DB error", error: err });
    if (result.length > 0) return res.json({ message: "Email already exists" });

    const hashed = await bcrypt.hash(password, 10);

    db.query(
      "INSERT INTO users (username, email, password, verified) VALUES (?, ?, ?, 0)",
      [username, email, hashed],
      async (err, result) => {
        if (err) return res.status(500).json({ message: "DB error", error: err });

        const userId = result.insertId;
        const token = jwt.sign({ id: userId }, process.env.JWT_SECRET, { expiresIn: "1d" });

        await sendVerificationEmail(email, token);

        res.json({ message: "Signup successful! Check email to verify." });
      }
    );
  });
});

// --------------------- EMAIL VERIFICATION ---------------------
app.get("/verify", (req, res) => {
  const { token } = req.query;

  if (!token) return res.send("Invalid link");

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.send("Token invalid or expired");

    const userId = decoded.id;

    db.query("UPDATE users SET verified=1 WHERE id=?", [userId], (err, result) => {
      if (err) return res.send("DB error");
      res.sendFile(path.join(__dirname, "../frontend/verify.html"));
    });
  });
});

// --------------------- LOGIN ---------------------
app.post("/login", (req, res) => {
  const { email, password } = req.body;

  db.query("SELECT * FROM users WHERE email=?", [email], async (err, result) => {
    if (err) return res.status(500).json({ message: "DB error", error: err });
    if (result.length === 0) return res.json({ message: "No account found" });

    const user = result[0];
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.json({ message: "Wrong password" });
    if (!user.verified) return res.json({ message: "Email not verified" });

    const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: "1d" });
    res.json({ message: "Login successful", token });
  });
});


// --------------------- FORGOT PASSWORD ---------------------
app.post("/request-reset", (req, res) => {
  const { email } = req.body;

  // Check if user exists
  db.query("SELECT * FROM users WHERE email=?", [email], async (err, result) => {
    if (err) return res.status(500).json({ message: "DB error" });
    if (result.length === 0) return res.json({ message: "No account with that email" });

    const user = result[0];
    const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: "1h" });

    const resetURL = `http://localhost:5000/reset-password.html?token=${token}`;

    const accessToken = await oauth2Client.getAccessToken();
    const transport = nodemailer.createTransport({
      service: "gmail",
      auth: {
        type: "OAuth2",
        user: process.env.EMAIL_USER,
        clientId: process.env.CLIENT_ID,
        clientSecret: process.env.CLIENT_SECRET,
        refreshToken: process.env.REFRESH_TOKEN,
        accessToken: accessToken,
      },
    });

    await transport.sendMail({
      from: `TechWeave <${process.env.EMAIL_USER}>`,
      to: email,
      subject: "Password Reset - TechWeave",
      html: `
        <h2>Password Reset</h2>
        <p>Click the link below to reset your password:</p>
        <a href="${resetURL}">Reset Password</a>
      `,
    });

    res.json({ message: "Password reset email sent!" });
  });
});

// --------------------- RESET PASSWORD ---------------------
app.post("/reset-password", (req, res) => {
  const { token, newPassword } = req.body;
  if (!token) return res.status(400).json({ message: "Invalid token" });

  jwt.verify(token, process.env.JWT_SECRET, async (err, decoded) => {
    if (err) return res.status(400).json({ message: "Token invalid or expired" });

    const hashed = await bcrypt.hash(newPassword, 10);
    db.query("UPDATE users SET password=? WHERE id=?", [hashed, decoded.id], (err, result) => {
      if (err) return res.status(500).json({ message: "DB error" });
      res.json({ message: "Password updated successfully" });
    });
  });
});





// --------------------- START SERVER ---------------------
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
