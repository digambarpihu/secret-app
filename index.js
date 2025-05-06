require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const app = express();

// Middleware
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use(cookieParser());

// Connect to MongoDB
mongoose.connect('mongodb://127.0.0.1:27017/secretsDB', { useNewUrlParser: true, useUnifiedTopology: true });

// User Schema
const userSchema = new mongoose.Schema({
  name: String,
  email: String,
  password: String
});

const User = mongoose.model('User', userSchema);

// Routes
app.get('/', (req, res) => {
  res.render('home');
});

app.get('/register', (req, res) => {
  res.render('register');
});

app.post('/register', async (req, res) => {
  const { name, email, password } = req.body;

  // Validate email
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res.send("❌ Invalid email format.");
  }

  // Validate password
  const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{6,8}$/;
  if (!passwordRegex.test(password)) {
    return res.send("❌ Password must be 6-8 chars, include uppercase, lowercase, and a number.");
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  const existingUser = await User.findOne({ email });
  if (existingUser) {
    return res.send("❌ User with this email already exists.");
  }

  const newUser = new User({
    name,
    email,
    password: hashedPassword
  });

  await newUser.save();
  res.redirect('/login');
});

app.get('/login', (req, res) => {
  res.render('login');
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });

  if (!user) {
    return res.send("❌ User not found.");
  }

  const match = await bcrypt.compare(password, user.password);

  if (!match) {
    return res.send("❌ Incorrect password.");
  }

  const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });

  res.cookie('token', token, { httpOnly: true });
  res.redirect('/protected');
});

// Middleware to check JWT token
function authenticate(req, res, next) {
  const token = req.cookies.token;
  if (!token) {
    return res.redirect('/login');
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.userId;
    next();
  } catch (err) {
    return res.redirect('/login');
  }
}

app.get('/protected', authenticate, async (req, res) => {
  const user = await User.findById(req.userId);
  res.render('protected', { user });
});

app.get('/logout', (req, res) => {
  res.clearCookie('token');
  res.redirect('/login');
});

app.listen(3000, () => {
  console.log("✅ Server running on http://localhost:3000");
});
