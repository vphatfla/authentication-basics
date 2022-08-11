/////// app.js
const express = require("express");
const path = require("path");
const session = require("express-session");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const mongoose = require("mongoose");
const { nextTick } = require("process");
const Schema = mongoose.Schema;
const bcrypt = require('bcryptjs');
const mongoDB = require('./mongoDB');


const URI = mongoDB.URI;
mongoose.connect(URI, { useUnifiedTopology: true, useNewUrlParser: true });
const db = mongoose.connection;
db.on("error", console.error.bind(console, "mongo connection error"));

const User = mongoose.model(
  "User",
  new Schema({
    username: { type: String, required: true },
    password: { type: String, required: true }
  })
);

passport.use(
    new LocalStrategy((username, password, done) => {
        User.findOne({ username: username}, (err, user) => {
            if (err) return done(err);

            if (!user) {
                return done(null, false, {message:"Incorrect username"});
            }

            bcrypt.compare(password,user.password, (err,res)=> {
                if (res){
                    // passwords match
                    
                    return done(null,user)
                }
                else{
                    // no match
                    return done(null,false, {message: "Incorrect password"})
                }
            })
        })
    })
)

passport.serializeUser(function(user,done) {
    done(null, user.id);
});

passport.deserializeUser(function(id,done) {
    User.findById(id, function(err,user){
        done(err,user);
    })
})
const app = express();
app.set("views", path.join(__dirname, 'views'));
app.set("view engine", "ejs");

app.use(session({ secret: "cats", resave: false, saveUninitialized: true }));
app.use(passport.initialize());
app.use(passport.session());
app.use(express.urlencoded({ extended: false }));

app.use(function(req, res, next) {
    res.locals.currentUser = req.user;
    next();
  });

app.get("/", (req, res) => 
    res.render("index", {user:req.user}));

app.get("/sign-up", (req,res) => res.render("sign-up-form"));

app.post('/sign-up', (req,res,next) => {
    let pw = req.body.password;
    bcrypt.hash(pw, 10, (err, hashedPassword) => {
        if (err) return next(err);
        const user = new User({
            username: req.body.username,
            password: hashedPassword,
        }).save(err => {
            if (err) return next(err);
            console.log(pw);
            res.redirect("/");
        })
    })
    
})

app.post(
    "/log-in",
    passport.authenticate("local", {
      successRedirect: "/",
      failureRedirect: "/"
    })
  );

app.get("/log-out", (req, res) => {
req.logout(function (err) {
    if (err) {
    return next(err);
    }
    res.redirect("/");
});
});
app.listen(3000, () => console.log("app listening on port 3000!"));