require('dotenv').config();
const express = require('express');
const ejs = require('ejs');
const mongoose = require('mongoose');
const app = express();
const port = process.env.PORT || 3000;
const encrypt = require('mongoose-encryption');
const md5 = require('md5');
const bcrypt = require('bcrypt');
const saltRounds = 10;
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');


app.use(express.static('public'));
app.set('view engine','ejs');
app.use(express.urlencoded({extended:true}));

app.use(session({//            session before connecting to mongodb
    secret: process.env.SECRET,
    resave: false,  // Forces the session to be saved back to the session store, even if the session was never modified during the request.
    saveUninitialized : false //the saveUninitialized option is set to false, the cookie will not be set on a response with an uninitialized session. This option only modifies the behavior when an existing session was loaded for the request.
}));

app.use(passport.initialize());
app.use(passport.session());


mongoose.set('strictQuery',false);
// mongoose.connect("mongodb://127.0.0.1:27017/userDB");
mongoose.connect(process.env.MONGODB_URI).catch(error => handleError(error));

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    secret: String,
    name: String
});

// console.log(process.env.API_KEY);

// userSchema.plugin(encrypt, {secret : process.env.SECRET, encryptedFields: ['password'] });

userSchema.plugin(passportLocalMongoose);//hash and salt password and save user into mongodb dbase
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

// passport.serializeUser(User.serializeUser());//create cookie for session
// passport.deserializeUser(User.deserializeUser());//check what inside cookie

passport.serializeUser(function(user, cb) {
    process.nextTick(function() {
      cb(null, { id: user.id, username: user.username });
    });
  });
  
passport.deserializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, user);
    });
  });

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: process.env.CALLBACK_URL
},
function(accessToken, referenceToken, profile, cb){
    // console.log(profile.displayName);//log the profile of user
    User.findOrCreate({googleId: profile.id,  name: profile.displayName}, function(err, user){//findOrCreate is a package like function  we have to install npm i mongoose-findorcreate
        return cb(err, user);
    });
}));

app.get('/', function(req, res){
    res.render("home");
});

app.get('/auth/google',//google sigin button send request via get to /auth/google
    passport.authenticate('google', {scope: ['profile']})//google stratagy we have defined above by id and key
);// google server asking for the profile

//google will reddirect to this callback route
app.get('/auth/google/secrets', // will complete it soon
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  }
);

app.get('/login', function(req, res){
    
    User.find({"secret": {$ne:null}}, function(err, foundUsers){
        if(err){
            console.log(err);
        }else{
            if(foundUsers){
                // console.log(foundUsers);
                if(foundUsers.length<500){
                    res.render('login');
                }else{
                    res.render('error');
                }
            }else{
                res.render('login');
            }
        }
    });
});

app.get('/register',(req, res)=>{
    User.find({"secret": {$ne:null}}, function(err, foundUsers){
        if(err){
            console.log(err);
        }else{
            if(foundUsers){
                // console.log(foundUsers);
                if(foundUsers.length<500){
                    res.render('register');
                }else{
                    res.render('error');
                }
            }else{
                res.render('register');
            }
        }
    });
});

// app.post('/register', function(req, res){
    
//     bcrypt.hash(req.body.password, saltRounds).then(function(hash) {
//         const newUser = new User({
//             email : req.body.username,
//             password : hash
//         });
//         newUser.save().then(()=>{res.render('secrets')}).catch((err)=>{res.send(err)});
//     });
// //         const newUser = new User({
// //         email : req.body.username,
// //         // password : md5(req.body.password)
// //         password : req.body.password
// //     });
// //     newUser.save().then(()=>{res.render('secrets')}).catch((err)=>{res.send(err)});
    
// });

app.get('/secrets', function(req, res){
    if(req.isAuthenticated()){
        User.find({"secret": {$ne:null}}, function(err, foundUsers){
            if(err){
                console.log(err);
            }else{
                if(foundUsers){
                    // console.log(foundUsers);
                    // console.log(foundUsers.length);

                    res.render('secrets', {usersWithSecret:foundUsers, btnName: "Log Out"});
                }
            }
        });
    }
    else{
        User.find({"secret": {$ne:null}}, function(err, foundUsers){
            if(err){
                console.log(err);
            }else{
                if(foundUsers){
                    // console.log(foundUsers);
                    // console.log(foundUsers.length);

                    res.render('secrets', {usersWithSecret:foundUsers, btnName: "Home"});
                }
            }
        });
    }
});

app.get('/submit', function(req, res){
    if(req.isAuthenticated()){
        res.render("submit");
    }else{
        res.redirect('/login');
    }
});

app.get('/error', function(req, res){
    res.render('error');
});

app.post('/submit', function(req, res){//passport autometically send details of user into req
    // const submittedSecret = req.body.secret;
    // console.log(req.user.id);//return id of user who save the detail
    User.updateOne({_id: req.user.id},{secret: req.body.secret}, function(err){
        if(err){
            res.send(err);
        }else{
            // console.log("updated");
            res.redirect('/secrets');
        }
    });
});

app.get('/logout', function(req, res){
    req.logout(function(err){
        if(err){
            return next(err);
        }
        res.redirect('/');
    })
});

app.get('/about', function(req, res){
    res.render('about');
});

app.get('/contact', function(req, res){
    res.render('contact');
});

app.post('/register', function(req, res){
    User.register({username: req.body.username},req.body.password, function(err,user){
        if(err){
            console.log(err);
            res.redirect('/register');
        }
        else{
            passport.authenticate('local')(req, res, function(){
                res.redirect('/secrets');
            });
        }
    });
});

app.post('/login', function(req, res){
    const user = new User({
        username: req.body.username,
        password: req.body.password
    });

    req.login(user, function(err){
        if(err){
            console.log(err);
        }
        else{
            passport.authenticate("local")(req, res, function(){//also save cookie into browser memory
                res.redirect('/secrets');
            });
        }
    });
});

// app.post('/login', function(req, res){

    
//     const userName = req.body.username;
//     // const password = md5(req.body.password);
//     const password = req.body.password;

//     User.findOne({email: userName}).then((doc)=>{
//         // if(doc.password === password)
//         // {
//         //     res.render('secrets');
//         // }
//         // else{
//         //     res.render('login');
//         // }
//         bcrypt.compare(password, doc.password).then(function(result) {
//             if(result === true){
//                 res.render('secrets');
//             }
//             else{
//                 res.render('login');
//             }
//         });
//     }).catch((err)=>{res.send(err)});
// })

app.listen(port, function(){
    console.log(`server is running http://localhost:${port}`);
});