//jshint esversion:6
require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const encrypt = require("mongoose-encryption");
const session= require("express-session");
const passport= require("passport");
const passportLocalMongoose= require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const passportFindOrCreate= require("mongoose-findorcreate");
const FacebookStrategy= require("passport-facebook");






const app = express().use(bodyParser.urlencoded({
    extended: true
}));
app.use(express.static('public'));
app.use(session({
    secret:"ranjan9748",
    resave:false,
    saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());
app.set('view engine', 'ejs');



mongoose.connect("mongodb://localhost:27017/secretUsers", {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    useCreateIndex: true

});

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    facebookId: String,
    secrets: [String]
});





userSchema.plugin(passportLocalMongoose);
userSchema.plugin(passportFindOrCreate);


const user = new mongoose.model("user", userSchema);

passport.use(user.createStrategy());


//passport.serializeUser(user.serializeUser());
//passport.deserializeUser(user.deserializeUser());

passport.serializeUser(function(user, done) {
  done(null, user);
});

passport.deserializeUser(function(user, done) {
  done(null, user);
});

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    user.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

passport.use(new FacebookStrategy({
    clientID: process.env.FB_APP,
    clientSecret: process.env.FB_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets"
},
function(accessToken, refreshToken, profile, cb) {
    user.findOrCreate({ facebookId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }

))





app.route("/")
    .get((req, res) => {
        res.render('home');
    })

app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile'] }));

app.get('/auth/google/secrets', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });

app.get('/auth/facebook',
  passport.authenticate('facebook'));

app.get('/auth/facebook/secrets',
  passport.authenticate('facebook', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });

app.route("/secrets")
    .get((req, res)=>{
        user.find({"secrets": {$ne: null}},(err, result)=>{
          if(err)
            console.log(err)
          else{
            res.render("secrets",{allSecrets : result});
          }
        })
    })

app.route("/submit")
  .get((req, res)=>{
  if(req.isAuthenticated())
    res.render("submit")
  else
    res.redirect("/login");
})
  .post((req, res)=>{
      const newSecret=req.body.secret;
      console.log(newSecret);
      const id=req.user._id;
      //user.findByIdAndUpdate({_id: id},{$push:{secrets: newSecret}});
      user.findOne({_id: id}, (err, result)=>{
        if(!err)
          result.secrets.push(newSecret);
          result.save(()=>{
            res.redirect("/secrets");
          });
      })


  })


app.route('/register')
    .get((req, res) => {
        res.render('register');
    })
    .post((req, res) => {
        user.register({username: req.body.username}, req.body.password,(err, user)=>{
            if(err){
               if(err.name==='UserExistsError')
                res.redirect('/login');
               else
                res.redirect('/register');
            }
            else{
                passport.authenticate('local')(req, res,()=>{
                    res.redirect("/secrets")
                })
            }
        })
    })

app.route('/logout')
    .get((req, res)=>{
        req.logout();
        res.redirect('/');
    })

app.route('/login')
    .get((req, res) => {
        res.render('login');
    })
    .post((req, res) => {

       const User= new user({
        email: req.body.username,
        password: req.body.password
       })

       req.login(User,(err)=>{
        if(err)
            console.log(err);
        else
            passport.authenticate('local')(req, res,()=>{
                    res.redirect("/secrets")
                })
       }) 
    })


app.listen(3000, () => {
    console.log("Connected to Server");
})