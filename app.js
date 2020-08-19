//jshint esversion:6
require('dotenv').config();
const express = require("express");
const ejs = require("ejs");
const mongoose = require("mongoose");
const bodyParser = require("body-parser");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const app = express();
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const findOrCreate = require('mongoose-find-or-create');
app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({
    extended: true
}));
////////////////////////////////////////////////////////////////////////////////////////////////////////
app.use(session({
    secret: "This is our little secret.",
    resave: false,
    saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());
mongoose.set('useCreateIndex', true);

mongoose.connect("mongodb+srv://admin-amged:"+process.env.DB_PASSWORD+"@cluster0-i3kie.mongodb.net/secretsDB", {
    useNewUrlParser: true,
    useUnifiedTopology: true
});
const userSchema = new mongoose.Schema({
    userName: String,
    password: String,
    googleId: String,
    facebookId: String,
    secret: []
});
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);
passport.use(User.createStrategy());


passport.serializeUser(function (user, done) {
    done(null, user.id);
});

passport.deserializeUser(function (id, done) {
    User.findById(id, function (err, user) {
        done(err, user);
    });
});


passport.use(new GoogleStrategy({
        clientID: process.env.CLIENT_IID,
        clientSecret: process.env.CLIENT_SSECRET,
        callbackURL: "/auth/google/secrets",
        userProfileURL: 'https://www.googleapis.com/oauth2/v3/userinfo',
    },
    function (accessToken, refreshToken, profile, cb) {
        User.findOrCreate({
            googleId: profile.id
        }, function (err, user) {
            return cb(err, user);
        });
    }
));
passport.use(new FacebookStrategy({
        clientID: process.env.FACEBOOK_APP_ID,
        clientSecret: process.env.FACEBOOK_APP_SECRET,
        callbackURL: "/auth/facebook/secrets"
    },
    function (accessToken, refreshToken, profile, cb) {
        User.findOrCreate({
            facebookId: profile.id
        }, function (err, user) {
            return cb(err, user);
        });
    }
));
/////////////////////////////////////////////////////////////////////////////////////////////////////////
app.get("/", function (req, res) {
        res.render("home");
});


app.get("/login", function (req, res) {
    if (req.isAuthenticated()) {
        res.redirect("/secrets");
    } else {
        res.render("login");
    }

});

app.get("/register", function (req, res) {
    if (req.isAuthenticated()) {
        res.redirect("/secrets");
    } else {
        res.render("register");
    }

});

app.get("/secrets", function (req, res) {
    User.find({
        secret: {
            $ne: null
        }
    }, function (err, foundUsers) {
        if (err) {
            console.log(err);
        } else {
            if (foundUsers) {
                res.render("secrets", {
                    usersWithSecrets: foundUsers
                });
            }
        }

    });


});

app.get("/logout", function (req, res) {
    req.logout();
    res.redirect("/");
});

app.get('/auth/google',
    passport.authenticate('google', {
        scope: ['profile']
    }));

app.get('/auth/google/secrets',
    passport.authenticate('google', {
        failureRedirect: '/login'
    }),
    function (req, res) {
        // Successful authentication, redirect home.
        res.redirect('/secrets');
    });

app.get("/submit", function (req, res) {
    if (req.isAuthenticated()) {
        res.render("submit");
    } else {
        res.redirect("login");
    }
});

app.post("/submit", function (req, res) {
    const submittedSecret = req.body.secret;
    User.findById(req.user.id, function (err, foundUser) {
        foundUser.secret.push(submittedSecret);
        foundUser.save();
    });
    res.redirect("secrets");
});

app.get('/auth/facebook',
    passport.authenticate('facebook'));

app.get('/auth/facebook/secrets',
    passport.authenticate('facebook', {
        failureRedirect: '/login'
    }),
    function (req, res) {
        // Successful authentication, redirect home.
        res.redirect('/secrets');
    });

app.post("/register", function (req, res) {
    User.register({
        username: req.body.username
    }, req.body.password, function (err, newUser) {
        if (err) {
            console.log(err);
            res.redirect("/register");
        } else {
            passport.authenticate("local")(req, res, function () {
                res.redirect("/secrets");
            });
        }
    });

});

app.post("/login", function (req, res) {
    const user = new User({
        username: req.body.username,
        password: req.body.password
    });
    req.login(user, function (err) {
        if (err) {
            console.log(err);
            res.redirect("/login");
        } else {
            passport.authenticate("local")(req, res, function () {
                res.redirect("/secrets");
            });
        }
    });
});
var port = process.env.PORT || 3000;
if (port == null || port == "") {
  port = 3000;
}
app.listen(port, function () {
    console.log("server has started on port 3000.");
});


