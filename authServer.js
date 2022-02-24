// this will allow us to pull params from .env file
require("dotenv").config()

const express = require('express')
const app = express()

const bcrypt = require('bcrypt')
const users = []

// this middleware will allow us to pull req.body.params
app.use(express.json())

// register a user
app.post("/createUser", async(req, res) => {
    const userName = req.body.name
        // $2b$10$SyCXFIDsoqqDsI4OTsZp3e5Gc6nZQni4ZApi1nFFHE08BBVFIy2o2
        // 2b - identifies the bcrypt algorithm version that was used
        // 10 - is the cost factor; 2^10 iterations of the key derivation function are used (which is not enough, by the way. I'd recommend a cost of 12 or more.)
        // The remaining characters are salt(first 22 characters) and the cipher text
    const hashedPassWord = await bcrypt.hash(req.body.password, 10)

    users.push({ userName: userName, hashedPassWord: hashedPassWord })
    res.status(201).send(users)
    console.log(users)
})

// authenticate login and return JWT token
// accessTokens
function generateAccessToken(user) {
    return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: "15m" })
}
//refreshTokens
let refreshTokens = []

function generateRefreshToken(user) {
    const refreshToken = jwt.sign(user, process.env.REFRESH_TOKEN_SECRET, { expiresIn: "20m" })
    refreshTokens.push(refreshToken)
    return refreshToken
}
const jwt = require("jsonwebtoken")
app.post("/login", async(req, res) => {
    // check to see if the user exists in the list of registered users
    const user = users.find((c) => c.userName == req.body.name)

    if (user == null) {
        res.status(404).send("user does not exist!!")
    }
    if (await bcrypt.compare(req.body.password, user.hashedPassWord)) {
        const accessToken = generateAccessToken({ userName: req.body.name })
        const refreshToken = generateRefreshToken({ userName: req.body.name })
        res.json({ accessToken: accessToken, refreshToken: refreshToken })
    } else {
        res.status(401).send("Password Incorrect!!")
    }
})

// refresh token api
app.post("/refreshToken", (req, res) => {
    if (!refreshTokens.includes(req.body.token)) {
        res.status(400).send("Refresh Token Invalid")
    }

    // remove the old refreshtoken from the refreshTokens list
    refreshTokens = refreshTokens.filter((c) => c != req.body.token)

    // generate new accessToken and refreshTokens
    const accessToken = generateAccessToken({ user: req.body.name })
    const refreshToken = generateRefreshToken({ user: req.body.name })

    res.json({ accessToken: accessToken, refreshToken: refreshToken })
})

app.delete("/logout", (req, res) => {
        //remove the old refreshToken from the refreshTokens list
        refreshTokens = refreshTokens.filter((c) => c != req.body.token)

        res.status(204).send("Logged out!")
    })
    // get port number from .env file
const port = process.env.TOKEN_SERVER_PORT
app.listen(port, () => {
    console.log(`Authrntication Server Running on ${port} ...`)
})