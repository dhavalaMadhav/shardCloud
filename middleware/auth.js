const { User, File } = require('../db/register')
const jwt = require("jsonwebtoken");
 const auth = async (req, res, next) => {
    try {
        const token = req.cookies.jwt;
        const verifyToken = jwt.verify(token, process.env.SECRET_KEY);
        const user = await User.findOne({ _id: verifyToken._id });
        req.user= user;
        next();
    } catch (err) {
        res.status(401).send("Unauthorized: No token provided");
    }
}
module.exports = auth;