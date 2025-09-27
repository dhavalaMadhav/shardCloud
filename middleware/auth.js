const jwt = require('jsonwebtoken');
const { User } = require('../db/register');

const auth = async (req, res, next) => {
  try {
    // Get token from cookie
    const token = req.cookies.jwt;
    
    if (!token) {
      console.log('No JWT token found in cookies');
      return res.redirect('/login');
    }

    // Verify token
    const decoded = jwt.verify(token, process.env.SECRET_KEY);
    console.log('Token decoded successfully:', decoded._id);
    
    // Find user and check if token exists in user's tokens array
    const user = await User.findOne({ 
      _id: decoded._id, 
      'tokens.token': token 
    });

    if (!user) {
      console.log('User not found or token invalid for user ID:', decoded._id);
      res.clearCookie('jwt');
      return res.redirect('/login');
    }

    // Set user on request object
    req.user = user;
    req.token = token;
    
    console.log(`Auth successful for user: ${user.email} (${user.name})`);
    next();
    
  } catch (error) {
    console.error('Auth middleware error:', error.message);
    
    // Clear invalid cookie and redirect
    res.clearCookie('jwt');
    return res.redirect('/login');
  }
};

module.exports = auth;
