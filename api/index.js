const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
require("dotenv").config();

const app = express();
app.use(express.json());
app.use(cors());

// Debug log URI
console.log("MONGODB_URI:", process.env.MONGODB_URI);

// Connect MongoDB
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => console.log("✅ MongoDB Connected"))
.catch(err => console.error("❌ MongoDB Error:", err));

// User schema
const User = mongoose.model("User", new mongoose.Schema({
  username: String,
  email: String,
  password: String
}));

// Routes
app.get("/", (req, res) => {
  res.send("✅ API is running!");
});

app.post("/api/register", async (req, res) => {
  const { username, email, password } = req.body;
  const user = new User({ username, email, password });
  await user.save();
  res.json({ message: "User registered!" });
});

app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email, password });
  if (!user) return res.status(401).json({ message: "Login failed" });
  res.json({ message: "Login success", user });
});

app.get("/api/user/:username", async (req, res) => {
  const user = await User.findOne({ username: req.params.username });
  if (!user) return res.status(404).json({ message: "User not found" });
  res.json({ username: user.username, email: user.email });
});

module.exports = app;