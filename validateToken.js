require("dotenv").config()

const express = require("express")
const app = express()
app.use(express.json())

const jwt = require("jsonwebtoken")

const port = process.env.PORT

function validateToken(req, res, next) {
    const token = req.headers["authorization"]

    if (token == null) {
        res.sendStatus(400).send("Token not present")
    }
    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user_payload) => {
        if (err) {
            res.status(403).send("Token invalid!!")
        } else {
            req.user = user_payload
            next()
        }
    })
}

app.get("/posts", validateToken, (req, res) => {
    console.log("Token is valid")
        // { user: 'konnchou', iat: 1645625945, exp: 1645626845 }
    console.log(req.user)
    res.send(`${req.user.userName} sucessfully accessed post!`)
})

app.listen(port, () => {
    console.log(`Validation server runing on ${port} ...`)
})