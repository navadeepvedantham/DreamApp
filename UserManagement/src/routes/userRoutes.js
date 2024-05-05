const express = require('express');
const router = express.Router();
const UserController = require('../controllers/userController');

// POST method to sign up
router.post('/signup', UserController.signup);

// GET method to check user by phone number
router.get('/check-phone', UserController.checkUserByPhoneNumber);

// GET method to retrieve user by email and password
router.get('/login', UserController.getUserByRoleEmailAndPassword);

// PUT method to update password with reset password link validation
router.put('/reset-password', UserController.forgotPassword);


module.exports = router;
