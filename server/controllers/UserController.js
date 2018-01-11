const { User } = require('../../db/models');
const axios = require('axios');
const bcrypt = require('bcrypt');
const passport = require('../../config/passport/passport.js');
const LocalStrategy = require('passport-local').Strategy;
const jwt = require('jsonwebtoken')
const JWT_SECRET = process.env.JWT_SECRET;

//The routes here for login, logout, and signup are working properly now.
UserController = {
  Login: (req, res, next) => {
    if (req.user) {
      res.status(200).send({ message: 'user is already logged in, let them know' });
    } else {
      passport.authenticate('local-login', function (err, user, info) {
        if (err) {
          return next(err); // will generate a 500 error
        }
        if (!user) {
          return res.status(200).send({
            errMsg: info.errMsg
          });
        }
        req.login(user, function (err) {

          let payload = {
            id: user.id
          }

          let options = {
            expiresIn: 86400 //24 hours
          }

          console.log('user login payload:', payload)

          var token = jwt.sign(payload, JWT_SECRET, options); 

          if (err) {
            console.error(err);
            return next(err);
          }
          return res.json({
            sucesss: true,
            message: 'log-in successful! Established a session with token',
            token: token
          });
        });
      })(req, res, next);
    }
  },

  Logout: (req, res, next) => {
    if (req.user) {
      req.logout();
      console.log('is auth after logout?', req.isAuthenticated());
      res.status(200).send({ message: 'logged out' });
    } else {
      res.status(200).send({ message: 'not logged in in the first place, redirect to homepage' });
    }
  },

  Signup: (req, res, next) => {
    if (req.user) {
      res.status(200).send({ message: 'user is already logged in, let them know' });
    } else {
      passport.authenticate('local-signup', function (err, user, info) {
        if (err) {
          return next(err); // will generate a 500 error
        }
        if (!user) {
          return res.status(200).send({
            errMsg: info.errMsg
          });
        }

        res.status(200).send({message:'you created a user!'})

        // if the below code is uncommented out, then you will immediately be logged in after creating a user.
        // if you do this, please remove "res.status(200).send(...)"" on the line above.



        // req.login(user, function (err) {

        //   let payload = {
        //     id: user.id
        //   }

        //   let options = {
        //     expiresIn: 86400 //24 hours
        //   }

        //   console.log('user login payload:', payload)

        //   var token = jwt.sign(payload, JWT_SECRET, options);

        //   if (err) {
        //     console.error(err);
        //     return next(err);
        //   }

        //   // send a json object with token as property. on client side, i set the token onto window.localStorage
        //   return res.json({
        //     sucesss: true,
        //     message: 'sign-up successful! Established a login session with token',
        //     token: token
        //   });
        // });

      })(req, res, next);
    }
  },

  FBSignup: (req, res, next) => {
    // if (req.user) {
    //   res.status(200).send({ message: 'user is already logged in, let them know' });
    // } else {
      passport.authenticate('facebook', { scope: ['email']}, function (err, user, info) {
        if (err) {
          return next(err); // will generate a 500 error
        }
        if (!user) {
          return res.status(200).send({
            errMsg: info.errMsg
          });
        }
        req.login(user, function (err) {

          let payload = {
            id: user.id
          }

          let options = {
            expiresIn: 86400 //24 hours
          }

          console.log('user login payload:', payload)

          var token = jwt.sign(payload, JWT_SECRET, options);

          if (err) {
            console.error('token err', err);
            return next(err);
          }

          // send a json object with token as property. on client side, i set the token onto window.localStorage
          return res.json({
            sucesss: true,
            message: 'sign-up successful! Established a login session with token',
            token: token
          });
        });
      })(req, res, next);
    // }
  }


};

module.exports = UserController;