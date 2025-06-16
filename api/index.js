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
  try {
    console.log("Register payload:", req.body);
    const { username, email, password } = req.body;
    if (!username || !email || !password) {
      return res.status(400).json({ message: "Please fill all fields" });
    }
    const user = new User({ username, email, password });
    await user.save();
    res.json({ message: "User registered!" });
  } catch (err) {
    console.error("Register error:", err);
    res.status(500).json({ message: "Internal server error" });
  }
});ß


app.post("/api/login", async (req, res) => {
  try {
    console.log("Login payload:", req.body);
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ message: "Email and password are required" });
    }

    const user = await User.findOne({ email, password });
    if (!user) {
      return res.status(401).json({ message: "Invalid email or password" });
    }

    res.json({ message: "Login successful", user });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ message: "Internal server error" });
  }
});


app.get("/api/user/:username", async (req, res) => {
  try {
    const { username } = req.params;
    console.log("Get user by username:", username);

    const user = await User.findOne({ username });
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    res.json({ user });
  } catch (err) {
    console.error("Get user error:", err);
    res.status(500).json({ message: "Internal server error" });
  }
});


module.exports = app;