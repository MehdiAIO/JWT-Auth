const express = require("express");
const mongoose = require("mongoose");
const jwt = require("jsonwebtoken");
require("dotenv").config();

// initializing app
const app = express();

app.use(express.json()); // parse incoming requests with json payloads and return


// Middleware to verify JWT
function verifyToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  console.log(token);
  if (!token) {
    return res.status(401).json({ message: "Token is missing" });
  }
  jwt.verify(token, process.env.SECRET_KEY, (err, decoded) => {
    if (err) {
      return res.status(401).json({ message: "Token is invalid" });
    }
    req.user = decoded;
    next();
  });  
}



// Protected Route
app.get("/protected", verifyToken, (req, res) => {
  res.json({ message: "You are authorized !" });
});



mongoose
  .connect(process.env.MONGO_URI)
  .then(() => {
    app.listen(process.env.PORT, () => {
      console.log(`runnin on port ${process.env.PORT}`);
    });
  })
  .catch((err) => console.log(err));
