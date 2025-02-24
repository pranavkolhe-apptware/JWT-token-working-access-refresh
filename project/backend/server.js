require("dotenv").config();
const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const cors = require("cors");
const cookieParser = require("cookie-parser");

const app = express();
app.use(express.json());
app.use(cors({ credentials: true, origin: "http://localhost:3000" }));
app.use(cookieParser());

const users = []; // Dummy in-memory storage
let refreshTokens = []; // Store refresh tokens temporarily

// Secret keys (use environment variables in production)
const ACCESS_TOKEN_SECRET = "my_access_secret";
const REFRESH_TOKEN_SECRET = "my_refresh_secret";

// Generate Access Token
const generateAccessToken = (user) => {
    console.log("users :",users);
  return jwt.sign(user, ACCESS_TOKEN_SECRET, { expiresIn: "10s" });
};

// Generate Refresh Token
const generateRefreshToken = (user) => {
  const refreshToken = jwt.sign(user, REFRESH_TOKEN_SECRET, { expiresIn: "30s" });
  refreshTokens.push(refreshToken);
  return refreshToken;
};

// Register API
app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  users.push({ username, password: hashedPassword });
  res.json({ message: "User registered" });
});

// Login API
app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  const user = users.find((u) => u.username === username);

  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(400).json({ error: "Invalid credentials" });
  }

  const accessToken = generateAccessToken({ username });
  const refreshToken = generateRefreshToken({ username });
  console.log("refreshTokens :",refreshToken);
  console.log("accessToken :",accessToken);
  res.cookie("refreshToken", refreshToken, { httpOnly: true, sameSite: "lax", secure: false });
  res.json({ accessToken });
});

// Refresh Token API
app.post("/refresh", (req, res) => {
  // const { token } = req.body;
  const token = req.cookies.refreshToken;
  console.log("refresh token consoled in /refresh for testing :",token);
  if (!token || !refreshTokens.includes(token)) {
    return res.status(403).json({ error: "Access Denied" });
  }

  jwt.verify(token, REFRESH_TOKEN_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    const accessToken = generateAccessToken({ username: user.username });
    res.json({ accessToken });
  });
});

// Protected Route
app.get("/protected", authenticateToken, (req, res) => {
  res.json({ message: "This is a protected route", user: req.user });
});

// Middleware to authenticate access token
function authenticateToken(req, res, next) {
  const token = req.headers["authorization"]?.split(" ")[1];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, ACCESS_TOKEN_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

app.listen(5000, () => console.log("Server running on port 5000"));
