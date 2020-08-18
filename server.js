const express = require("express");
const app = express();
const {pool} = require("./dbConfig");
const PORT = process.env.PORT || 4000;
const cors = require('cors');
const bcrypt = require("bcrypt");
const session = require("express-session");
// const flash = require("express-flash");
const passport = require("passport");
const initializePassport = require("./passportConfig");

initializePassport(passport);
   
// app.set("view engine", "ejs");
// app.use(express.urlencoded({ extended: true}));
app.use(express.json());
app.use(cors());
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false
}))
app.use(passport.initialize());
app.use(passport.session());
// app.use(express.static( __dirname + "/public"));
// app.use(flash());

// app.use(function(req, res, next){               // should be used just before first get request
//     res.locals.currentUser = req.user;
//     res.locals.error = req.flash("error");
//     res.locals.success = req.flash("success_msg");
//     next();
//     });

// app.get("/", (req, res) => {
//     res.render("index");
// });

// app.get("/users/dashboard", isLoggedIn, (req, res) => {
//     res.render("dashboard", {user: req.user.name});
// });

// app.get("/users/register", isNotLoggedIn, (req, res) => {
//     res.render("register");
// });

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
        res.status(400).json(errors);
    } else {
        let hash = await bcrypt.hash(password, 10);
        pool.query (
            `SELECT * FROM users
            WHERE email = $1`, [email]
        )
        .then((results) => {
            if (results.rows.length >0) {
                errors.push({message: "Email is already registered"});
                res.status(400).json(errors);
            } else {
                pool.query(
                    `INSERT INTO users (name, email, password) VALUES ($1, $2, $3) RETURNING (id, password)`,
                    [name, email, hash]
                )
                .then((results)=>{
                    pool.query (
                        `SELECT * FROM users
                        WHERE email = $1`, [email]
                    )
                    .then(results => {
                        res.json(results.rows[0]);
                    })                    
                })
                .catch(err => {
                    res.status(400).json("Something went wrong. Please try again");
                })                        
            }
        } )
        .catch(err => {
            res.status(400).json("User cannot be registered. Please try again");
        })        
    }
})

// app.get("/users/login", isNotLoggedIn, (req, res) => {
//     res.render("login");
// });

// app.post("/users/login",
//     passport.authenticate("local", {
//     successRedirect:"/users/dashboard",
//     failureRedirect:"/users/login",
//     failureFlash: true
// })
// passport.authenticate("local"), (req, res) => {
//     res.json(req.user)
// }
// );

app.post('/users/login', function(req, res, next) {
    passport.authenticate('local', function(err, user, info) {
      if (err) { return next(err); }
      if (!user) { return res.status(400).json("Incorrect Username or Password") }
      req.logIn(user, function(err) {
        if (err) { return next(err); }
        return res.json({user: user, success_msg: `welcome ${user.name}`});
      });
    })(req, res, next);
  });

app.get("/users/logout", (req, res) => {
    req.logout();
    res.json({success_msg: "you have successfully loggedout"})
})

// function isNotLoggedIn (req, res, next)  {
//     if (req.isAuthenticated()) {
//         return res.redirect("/users/dashboard")
//     }
//     next()
// }

// function isLoggedIn (req, res, next) {
//     if (req.isAuthenticated()) {
//         return next()
//     }
//     res.redirect("/users/login")
// }

app.listen(PORT, ()=> {
    console.log(`Server started on port number ${PORT}`);
})