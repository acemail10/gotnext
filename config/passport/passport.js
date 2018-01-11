const passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;
var FacebookStrategy = require('passport-facebook').Strategy;
const bcrypt = require('bcrypt');
const {User} = require('../../db/models');
const CLIENT_ID = process.env.FACEBOOK_CLIENT_ID;
const CLIENT_SECRET = process.env.FACEBOOK_CLIENT_SECRET;


passport.serializeUser(function (user, done) {
  console.log('this is user', user);
  done(null, user.id);
});

passport.deserializeUser(function (id, done) {
  console.log('deserialuser', id);
  User.findOne({
      where: {
        id: id
      }
    })
    .then((userdata) => {
      done(null, userdata);
    })
    .catch((err) => {
      if (err) {
        throw err;
      }
    });
});

passport.use('local-signup', new LocalStrategy({
    usernameField: 'username',
    passwordField: 'password',
    passReqToCallback: true
  },
  function (req, username, password, done) {
    process.nextTick(function () {
      bcrypt.hash(req.body.password, 10, (err, hash) => {
        if (err) {
          console.log('sign up error', err);
        } else {
          User.findOrCreate({
              where: {
                username: req.body.username
              },
              defaults: {
                password: hash
              }
            })
            .spread((result, created) => {
              if (!created) {
                console.log('Email already taken');
                return done(null, false, {
                  errMsg: 'email already exists'
                });
                // res.status(200).send(created);
              } else {
                console.log('Login successful!', result.dataValues);
                return done(null, result.dataValues);
                // res.status(200).send(result);
              }
            });
        }
      });
    });
  }));

passport.use('local-login', new LocalStrategy({
    usernameField: 'username',
    passwordField: 'password',
    passReqToCallback: true
  },
  function (req, username, password, done) {
    process.nextTick(function () {
      User.findOne({
          where: {
            username: req.body.username
          }
        })
        .then((userdata) => {
          console.log('userdata', userdata);
          if (userdata === null) {
            return done(null, false, {errMsg: 'user does not exist'});
          } else {
            bcrypt.compare(req.body.password, userdata.dataValues.password, function (err, result) {
              if (err) {
                console.log('error signing up', err);
                // res.status(500).send({message: 'error signing up'});
              } else if (!!result) {
                console.log('successful sign in');
                return done(null, userdata);
                // res.status(201).send({message: 'successful sign in'});
              } else {
                console.log('invalid password');
                return done(null, false, {errMsg: 'invalid password'});
                // res.status(500).send({message: 'unsuccessful sign in'});
              }
            });
          }
        })
        .catch((err) => {
          console.log('error finding user for login', err);
          done(null, false, {errMsg: 'user not found'});
        });
    });
  }));

  passport.use(new FacebookStrategy({
    clientID: CLIENT_ID, //'abc', //process.env.CLIENT_ID,
    clientSecret: CLIENT_SECRET, //'abc', //process.env.CLIENT_SECRET,
    callbackURL: 'http://localhost:3000/api/user/fb/signup/return', // 'http://localhost:3000/login/facebook/return'
    profileFields: ['emails']
  },
  // function(accessToken, refreshToken, profile, cb) {
  function(accessToken, refreshToken, profile, done) {
    process.nextTick(function () {
      console.log('this is profile', profile);
      User.findOrCreate({
          where: {
            username: profile.emails[0].value
          },
          defaults: {
            password: null
          }
        })
        .spread((result, created) => {
          if (!created) {
            console.log('Email already taken');
            return done(null, false, {
              errMsg: 'email already exists'
            });
            // res.status(200).send(created);
          } else {
            console.log('Login successful!', result.dataValues);
            return done(null, result.dataValues);
            // res.status(200).send(result);
          }
        });
    });
    // In this example, the user's Facebook profile is supplied as the user
    // record.  In a production-quality application, the Facebook profile should
    // be associated with a user record in the application's database, which
    // allows for account linking and authentication with other identity
    // providers.
    return cb(null, profile);
  }));








// console.log('before passport use');
// passport.use('local', new LocalStrategy(localOptions, async (username, password, done) => {
//     console.log('please work');
// }));

module.exports = passport;