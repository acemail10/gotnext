const express = require('express');
const Router = express.Router();
const UserController = require('./controllers/userController.js');
const MapContoller = require('./controllers/MapController.js');
const GamesController = require('./controllers/GamesController.js');

// [[ U S E R ]]

Router.route('/user/login')
  .post(UserController.Login);

Router.route('/user/logout')
  .get(UserController.Logout);

Router.route('/user/signup')
  .post(UserController.Signup);


// [[ M A P ]]

// on componentDidMount  
Router.route('/map/fetch/zip/:zip')
  .get(MapContoller.Fetch);


// [[ G A M E ]]

// on componentDidMount
Router.route('/games/fetch/:zip')
  .get(GamesController.FetchList);

Router.route('/games/create')
  .post(GamesController.CreateGame);

// user view
Router.route('/games/fetch/user/:username')
  .get(GamesController.FetchUserList)

module.exports = Router;
