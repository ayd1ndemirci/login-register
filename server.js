const express = require("express");
const sqlite = require("sqlite3").verbose();
const bcrypt = require("bcrypt");
const session = require("express-session");
const path = require("path");
const bodyParser = require("body-parser");

const app = express();
const db = new sqlite.Database("./database.db");


app.use(bodyParser.urlencoded({ extended: false }));
app.use(express.static("public"));
app.use(session({
    secret: "super secret key",
    resave: false,
    saveUninitialized: true
}));

db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT
)`);

app.use(express.static(path.join(__dirname, 'public')));

app.get("/register", (req, res) => {
    res.sendFile(path.join(__dirname, "views", "register.html"));
});

app.get("/login", (req, res) => {
    res.sendFile(path.join(__dirname, "views", "login.html"));
});

app.post("/register", (req, res) => {
    const { username, password } = req.body;
    const hashedPassword = bcrypt.hashSync(password, 10);

    db.run(`INSERT INTO users (username, password) VALUES (?, ?)`, [username, hashedPassword], function (err) {
        if (err) {
            return res.send("Bu kullanıcı adı zaten alınmış.");
        }
        res.redirect("/login");
    });
});

app.post("/login", (req, res) => {
    const { username, password } = req.body;

    db.get(`SELECT * FROM users WHERE username = ?`, [username], (err, user) => {
        if (err || !user) {
            return res.send("Kullanıcı adı veya şifre yanlış.");
        }

        if (bcrypt.compareSync(password, user.password)) {
            req.session.userId = user.id;
            res.redirect("/dashboard");
        } else {
            res.send("Kullanıcı adı veya şifre yanlış.");
        }
    });
});

app.get("/dashboard", (req, res) => {
    if (!req.session.userId) {
        return res.redirect("/login");
    }

    res.send("Merhaba, Kullanıcı ID: " + req.session.userId);
});

const PORT = 31;

app.listen(PORT, () => {
    console.log("Server listening on port " + PORT);
});