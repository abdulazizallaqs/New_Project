const express = require("express");
const app = express();
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const { v4: uuidv4 } = require("uuid");
const port = 3001;
app.use(express.json());

app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});

const users = [];
const refreshTokens = [];

const ACCESS_SECRET = "access_secret";
const REFRESH_SECRET = "refresh_secret";

app.post("/Register", async (req, res) => {
    const { email, password } = req.body;

    const hashed_password = await bcrypt.hash(password, 10);

    users.push({ email, hashed_password });
    res.status(201).send("User Registered Successfully");
});

app.post("/login", async (req, res) => {
    const { email, password } = req.body;

    const user = users.find(u => u.email == email);

    if (!user) {
        return res.status(400).send("User Not Found");
    }
    const matched = await bcrypt.compare(password, user.hashed_password);

    if (!matched) {
        return res.status(400).send("Invalid Password");
    }

    const accessToken = jwt.sign({ email }, ACCESS_SECRET, {
        expiresIn: "15m"
    });
    const refreshToken = jwt.sign({ email }, REFRESH_SECRET, {
        expiresIn: "7d"
    });

    refreshTokens.push(refreshToken);
    res.json({ accessToken, refreshToken });
});

function authenticateToken(req, res, next) {
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1];

    if (!token)
        return res.status(401).send("No Token");

    jwt.verify(token, ACCESS_SECRET, (err, user) => {
        if (err)
            return res.status(403).send("Invalid Token");
        req.user = user;
        next();
    })
}

app.post("/token", (req, res) => {
    const refreshToken = req.body.refreshToken;
    if (!refreshToken)
        return res.status(401).send("No Token");

    if (!refreshTokens.includes(refreshToken))
        return res.status(403).send("Invalid Token");

    jwt.verify(refreshToken, REFRESH_SECRET, (err, user) => {
        if (err)
            return res.status(403).send("Invalid Token");
        const accessToken = jwt.sign({ email: user.email }, ACCESS_SECRET, { expiresIn: "15m" });
        res.json({ accessToken });
    })
});

app.post("/checktoken", authenticateToken, (req, res) => {
    res.send("Valid Token");
});

app.post("/logout", (req, res) => {
    const refreshToken = req.body.refreshToken;
    if (!refreshToken)
        return res.status(401).send("No Token");

    if (!refreshTokens.includes(refreshToken))
        return res.status(403).send("Invalid Token");

    const index = refreshTokens.indexOf(refreshToken);
    if (index > -1) {
        refreshTokens.splice(index, 1);
    }
    res.send("Logged out successfully");
});
