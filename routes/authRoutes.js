const express = require('express');
const { register, login, getUser } = require('../controllers/authController');
const verifyToken = require('../middleware/authMiddleware');

const router = express.Router();

router.post('/register', register);
router.post('/login', login);
router.get('/me', verifyToken, getUser);

module.exports = router;
