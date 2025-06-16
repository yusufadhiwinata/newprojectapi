const connectDB = require('../../utils/db');
const User = require('../../models/User');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

exports.handler = async function(event) {
  try {
    const { email, password } = JSON.parse(event.body);
    await connectDB();

    const user = await User.findOne({ email });
    if (!user) return { statusCode: 400, body: JSON.stringify({ message: 'Email tidak ditemukan' }) };

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return { statusCode: 400, body: JSON.stringify({ message: 'Password salah' }) };

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1d' });

    return {
      statusCode: 200,
      body: JSON.stringify({ token })
    };
  } catch (err) {
    return { statusCode: 500, body: JSON.stringify({ error: err.message }) };
  }
};
