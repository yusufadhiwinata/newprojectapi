const connectDB = require('../../utils/db');
const User = require('../../models/User');
const bcrypt = require('bcryptjs');

exports.handler = async function(event, context) {
  try {
    const { username, email, password } = JSON.parse(event.body);

    await connectDB();

    const existing = await User.findOne({ email });
    if (existing) {
      return {
        statusCode: 400,
        body: JSON.stringify({ message: 'Email sudah digunakan' })
      };
    }

    const hashed = await bcrypt.hash(password, 10);

    const user = new User({ username, email, password: hashed });
    await user.save();

    return {
      statusCode: 201,
      body: JSON.stringify({ message: 'Registrasi berhasil' })
    };

  } catch (err) {
    return { statusCode: 500, body: JSON.stringify({ error: err.message }) };
  }
};
