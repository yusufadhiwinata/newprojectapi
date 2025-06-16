const connectDB = require('../../utils/db');
const User = require('../../models/User');
const jwt = require('jsonwebtoken');

exports.handler = async function(event) {
  try {
    const authHeader = event.headers.authorization || '';
    const token = authHeader.split(' ')[1];
    if (!token) return { statusCode: 401, body: 'Unauthorized' };

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    await connectDB();

    const user = await User.findById(decoded.id).select('-password');
    return {
      statusCode: 200,
      body: JSON.stringify(user)
    };

  } catch (err) {
    return { statusCode: 401, body: 'Unauthorized' };
  }
};
