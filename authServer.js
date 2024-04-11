const express = require("express");
const mongoose = require("mongoose");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
require("dotenv").config();

const User = require("./models/user.model.js");


// initializing app
const app = express();

 // parse incoming requests with json payloads and return
app.use(express.json());


let refreshTokens=[];


// Signup Endpoint
app.post("/signup", async (req, res) => {
  try {
    const hashedPass = await bcrypt.hash(req.body.password, 10); // Increase the number of rounds for stronger hashing
    const user = await User.create({
      username: req.body.username,
      password: hashedPass,
    }); // Await here
    res.status(201).json({ message: "User created successfully", user });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Login Endpoint
app.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });

    if (!user) {
      return res.status(401).json({ message: "Invalid username or password" });
    }

    const match = await bcrypt.compare(password, user.password); // Compare with user.password

    if (match) {
      const user = {username : req.body.username};
      const accessToken = generateAccessToken(user);
      const refreshToken = generateRefreshToken(user);
      refreshTokens.push(refreshToken);
      res.status(200).json({ accessToken,refreshToken });
    } else {
      res.status(401).json({ message: "Invalid username or password" });
    }
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// regenerate accessToken Endpoint
app.post("/token", (req, res) => {
  const refreshToken = req.body.token;
  if (!refreshToken) {
      return res.status(400).json({ message: "Refresh token is missing" });
  }
  if (!refreshTokens.includes(refreshToken)) {
      return res.status(403).json({ message: "Invalid refresh token" });
  }
  jwt.verify(refreshToken, process.env.REFRESH_KEY, (err, user) => {
      if (err) {
          return res.status(403).json({ message: "Invalid refresh token" });
      }
      const newAccessToken = generateAccessToken({ username: user.username });
      res.status(200).json({ accessToken: newAccessToken });
  });
});



// logout endpoint
app.delete('/logout',(req,res) => {
    refreshTokens.filter(token => token !== req.body.token);
    res.status(201).json({message:"Logged out successfully."});
});


// generate accessToken
function generateAccessToken(user){
  return jwt.sign(user,process.env.SECRET_KEY,{expiresIn : 60});
}

// generate refreshToken
function generateRefreshToken(user){
  return jwt.sign(user,process.env.REFRESH_KEY);
}

mongoose
  .connect(process.env.MONGO_URI)
  .then(() => {
    app.listen(3600, () => {
      console.log(`runnin on port 3600`);
    });
  })
  .catch((err) => console.log(err));
