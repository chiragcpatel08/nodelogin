const passport = require("passport");

const LocalStrategy = require("passport-local").Strategy;
const {pool} = require("./dbConfig");
const bcrypt = require("bcrypt");

const initialize = (passport) => {
    const authenticateUser = (email, password, done) => {
        pool.query(
            `SELECT * FROM users WHERE email=$1`,[email] 
        )
        .then((results) => {
            if(results.rows.length > 0) {
                const user = results.rows[0];
                bcrypt.compare(password, user.password)
                .then((isPasswordMatch) => {
                    if(isPasswordMatch) {
                        return done(null, user);
                    } else {
                        return done(null, false, {message: "Password is incorrect"});
                    }                    
                })
                .catch(err => {
                    return done(err);
                })
            } else {
                return done(null, false, {message: "Email is not registered"});
            }
        })
        .catch((err) => {
            return done(err);
        })
    }

    passport.use (new LocalStrategy(
        {
        usernameField: "email",
        passwordField: "password"
    }, 
    authenticateUser)
    );

    passport.serializeUser((user, done) => {
        done(null, user.id);
    });

    passport.deserializeUser((id, done) => {
      pool.query(
          `SELECT * FROM users WHERE id=$1`, [id]
      )
      .then(results => {
          return done(null, results.rows[0])
      })
      .catch(err => {
          return done(err);
      })
    });
}

module.exports = initialize;