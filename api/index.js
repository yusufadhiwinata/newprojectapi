const express = require("express");
const serverless = require("serverless-http");
const mongoose = require("mongoose");
const cors = require("cors");
require("dotenv").config();

const app = express();
app.use(express.json());
app.use(cors());

// Connect ke MongoDB Atlas
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log("✅ Connected to MongoDB"))
  .catch(err => console.error("❌ MongoDB error:", err));

// Skema user sederhana
const User = mongoose.model("User", new mongoose.Schema({
  username: String,
  email: String,
  password: String
}));

// Route registrasi
app.post("/api/register", async (req, res) => {
  const { username, email, password } = req.body;
  const user = new User({ username, email, password });
  await user.save();
  res.json({ message: "User registered!" });
});

// Route login (sederhana, belum pakai JWT)
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email, password });
  if (!user) return res.status(401).json({ message: "Login failed" });
  res.json({ message: "Login success", user });
});

app.get("/api/user/:username", async (req, res) => {
  const { username } = req.params;
  const user = await User.findOne({ username });

  if (!user) {
    return res.status(404).json({ message: "User not found" });
  }

  // Tidak kirim password untuk alasan keamanan
  res.json({
    username: user.username,
    email: user.email
  });
});

module.exports = app;
module.exports.handler = serverless(app);
