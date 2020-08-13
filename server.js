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
app.use(express.static( __dirname + "/public"));
app.use(flash());

app.use(function(req, res, next){               // should be used just before first get request
    res.locals.currentUser = req.user;
    res.locals.error = req.flash("error");
    res.locals.success = req.flash("success_msg");
    next();
    });

app.get("/", (req, res) => {
    res.render("index");
});

app.get("/users/dashboard", isLoggedIn, (req, res) => {
    res.render("dashboard", {user: req.user.name});
});

app.get("/users/register", isNotLoggedIn, (req, res) => {
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
        errors.push({message: "Password should be atleast 5 characters"})
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

app.get("/users/login", isNotLoggedIn, (req, res) => {
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

function isNotLoggedIn (req, res, next)  {
    if (req.isAuthenticated()) {
        return res.redirect("/users/dashboard")
    }
    next()
}

function isLoggedIn (req, res, next) {
    if (req.isAuthenticated()) {
        return next()
    }
    res.redirect("/users/login")
}

app.listen(PORT, ()=> {
    console.log(`Server started on port number ${PORT}`);
})