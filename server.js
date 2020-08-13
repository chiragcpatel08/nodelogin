const express = require("express");
const app = express();
const {pool} = require("./dbConfig");
const PORT = process.env.PORT || 4000;
const bcrypt = require("bcrypt");
const session = require("express-session");
const flash = require("express-flash");
const passport = require("passport");
const initializePassport = require("./passportConfig");

initializePassport(passport);

app.set("view engine", "ejs");
app.use(express.urlencoded({ extended: true}));
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false
}))
app.use(passport.initialize());
app.use(passport.session());
app.use(flash());

app.get("/", (req, res) => {
    res.render("index");
});

app.get("/users/dashboard", checkNotAuthenticated, (req, res) => {
    res.render("dashboard", {user: req.user.name});
});

app.get("/users/register", checkAuthenticated, (req, res) => {
    res.render("register");
});

app.post("/users/register", async (req, res) => {
    let {name, email, password, password1} = req.body;
    let errors = [];

    if(!name || !email || !password || !password1) {
        errors.push({message: "Fields should not be empty"})
    }

    if(password != password1) {
        errors.push({message: "passwords do not match"})
    }   

    if(password.length < 5) {
        errors.push({message: "Password should be atleast 6 character"})
    }

    if(errors.length > 0) {
        res.render("register", {errors})
    } else {
        let hash = await bcrypt.hash(password, 10);
        pool.query (
            `SELECT * FROM users
            WHERE email = $1`, [email]
        )
        .then((results) => {
            if (results.rows.length >0) {
                errors.push({message: "Email is already registered"});
                res.render("register", {errors});
            } else {
                pool.query(
                    `INSERT INTO users (name, email, password) VALUES ($1, $2, $3) RETURNING (id, password)`,
                    [name, email, hash]
                )
                .then((results)=>{
                    req.flash("success_msg", "You are successfully registered")
                    res.redirect("/users/login")
                })
                .catch(err => console.log(err))                        
            }
        } )
        .catch(err => console.log(err))        
    }
})

app.get("/users/login", checkAuthenticated, (req, res) => {
    res.render("login");
});

app.post("/users/login",
    passport.authenticate("local", {
    successRedirect:"/users/dashboard",
    failureRedirect:"/users/login",
    failureFlash: true
})
// passport.authenticate("local"), (req, res) => {
//     res.send(req.user)
// }
);

app.get("/users/logout", (req, res) => {
    req.logout();
    req.flash("success_msg", "You have successfully logged out");
    res.redirect("/users/login");
})

function checkAuthenticated (req, res, next)  {
    if (req.isAuthenticated()) {
        return res.redirect("/users/dashboard")
    }
    next()
}

function checkNotAuthenticated (req, res, next) {
    if (req.isAuthenticated()) {
        return next()
    }
    res.redirect("/users/login")
}

app.listen(PORT, ()=> {
    console.log(`Server started on port number ${PORT}`);
})