const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');

const app = express();
const port = 3000;

app.use(cors());
app.use(bodyParser.json());

let user = {
  nama: "John Doe",
  email: "john@example.com",
  password: "123456"
};

// REGISTER
app.post('/register', (req, res) => {
  const { nama, email, password } = req.body;
  user = { nama, email, password };
  res.status(201).json({ message: 'User registered successfully', user });
});

// LOGIN
app.post('/login', (req, res) => {
  const { email, password } = req.body;
  if (email === user.email && password === user.password) {
    res.json({ message: 'Login successful', user });
  } else {
    res.status(401).json({ message: 'Invalid email or password' });
  }
});

// LUPA PASSWORD
app.post('/forgot-password', (req, res) => {
  const { email } = req.body;
  if (email === user.email) {
    res.json({ message: 'Password reset link sent to email' });
  } else {
    res.status(404).json({ message: 'Email not found' });
  }
});

// GANTI PASSWORD
app.put('/change-password', (req, res) => {
  const { password } = req.body;
  user.password = password;
  res.json({ message: 'Password updated successfully' });
});

// HOME
app.get('/home', (req, res) => {
  res.json({ nama: user.nama });
});

app.listen(port,'0,0,0,0',() => {
  console.log(`🚀 Fake API is running at http://localhost:${port}`);
});
