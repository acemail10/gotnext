const jwt = require('jsonwebtoken')
const JWT_SECRET = process.env.JWT_SECRET;

// this is a helper middleware function that will check if a token exists/is not expired.

var tokenExists = function (req, res, next) {
  console.log('meow meow');
  // check header or url parameters or post parameters for token
  // we are set up to have the token stored in req.body.token
  var token = req.token || req.body.token || req.query.token || req.headers.token || req.headers['x-access-token'];
  console.log('Current Token:', req.body.token) 
  // decode token
  if (token) {

    // verifies secret and checks exp
    jwt.verify(token, JWT_SECRET, function (err, decoded) {
      if (err) {
        console.log('Token Error:', err.name + ' ' + err.message)
        return res.json({ success: false, message: 'Failed to authenticate token.' });
      } else {
        console.log('Token is still active!')
        // if everything is good, save to request for use in other routes
        console.log('req.decoded before:', req.decoded)
        req.decoded = decoded;
        console.log('req.decoded after:', req.decoded)
        console.log('decoded:', decoded)
        
        next();
      }
    });

  } else {

    // if there is no token
    // return an error
    return res.status(200).send({
      success: false,
      message: 'No token provided.'
    });

  }
}

module.exports = tokenExists