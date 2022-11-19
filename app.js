require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const session = require('express-session');
//The Passport JS framework abstracts the Login process into 2 separate parts, 
// the “session management” (done by the “Passport JS library” ), and the “authentication” 
// (done by the secondary “Strategy” library eg. “passport-local” or “passport-facebook” or “passport-oauth-google” etc.)
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const findOrCreate = require('mongoose-findorcreate');

const app = express();

app.set('view engine', 'ejs');

app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));


app.use(session({                   // This is the basic "express session"({..}) initialization
    secret: process.env.SECRET,
    resave: false,
    saveUninitialized: true
}));
app.use(passport.initialize());    // init passport on every route call
app.use(passport.session());       // allow passport to use "express-session"


mongoose.connect("mongodb://localhost:27017/userDB");


const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,       // this property is needed to store the google
    facebookId: String,     // and facebook identity of the user
    secret: String          // the secret, the user will share in the webapp
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());        // passport-local-mongoose is doing things easy for us, else we had to define a strategy

passport.serializeUser(function (user, done) {  // This allows the authenticated user to be "attached" to a unique session
    done(null, user.id);
});

passport.deserializeUser(function (id, done) {  // this function checks if the id of the user exists in the req.user
    User.findById(id, function (err, user) {    // if so, it refers that the user's session cookie is active
        done(err, user);
    });
});

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets"
},
    function (accessToken, refreshToken, profile, cb) {

        User.findOrCreate({ googleId: profile.id }, function (err, user) {
            return cb(err, user);
        });
    }
));

passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets"
},
    function (accessToken, refreshToken, profile, cb) {
        User.findOrCreate({ facebookId: profile.id }, function (err, user) {
            return cb(err, user);
        });
    }
));

app.get("/", function (req, res) {
    res.render("home");
});

app.get("/auth/google",
    passport.authenticate('google', { scope: ["profile"] })
);

app.get("/auth/google/secrets", passport.authenticate('google', {
    successRedirect: '/secrets',
    failureRedirect: '/login'
}));

app.get('/auth/facebook',
    passport.authenticate('facebook'));

app.get('/auth/facebook/secrets', passport.authenticate('facebook', {
    successRedirect: '/secrets',
    failureRedirect: '/login'
}));


app.get("/logout", function (req, res) {
    req.logout(function (err) {
        if (err) return next(err);
        res.redirect('/');
    });
});

app.get("/secrets", function (req, res) {
    if (req.isAuthenticated()) {    // retrieves the session cookie and checks if the session is still active or not
        User.find({ secret: { $ne: null } }, (err, results) => {
            if (!err && results) res.render("secrets", { usersWithSecrets: results });
        });
    } else {
        res.redirect("/login");
    }
});


app.route('/register')

    .get(function (req, res) {
        res.render("register");
    })

    .post(function (req, res) {

        // passport-local-mongoose is doing the heavy lifting for us with this function
        User.register({ username: req.body.username }, req.body.password, (err, user) => {
            if (err) {
                console.log(err);       // err will occur when the user is already registered
                res.redirect("/login");
            } else {
                passport.authenticate("local")(req, res, () => res.redirect("/secrets"));
                // saves current logged in session and sends the seesion cookie to the browser
            }
        });

    });


app.route('/login')

    .get(function (req, res) {
        if (req.isAuthenticated()) res.redirect("/secrets");
        else res.render("login");
    })

    .post(passport.authenticate('local', {
        successRedirect: '/secrets',
        failureRedirect: '/login'
    }));


app.route('/submit')

    .get(function (req, res) {
        if (req.isAuthenticated()) {    // retrieves the session cookie and checks if the session is still active or not
            res.render("submit");
        } else {
            res.redirect("/login");
        }
    })

    .post(function (req, res) {
        const submittedSecret = req.body.secret;

        User.findByIdAndUpdate(req.user.id, { secret: submittedSecret }, (err) => {
            if (!err) res.redirect("/secrets");
        })
    });



let port = process.env.PORT;
if (port == null || port == "") {
    port = 3000;
}
app.listen(port);