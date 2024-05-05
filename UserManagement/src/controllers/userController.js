const User = require('../models/User');
const bcrypt = require('bcrypt');

exports.signup = async (req, res) => {
    try {
        const {
            username,
            email,
            password,
            fullName,
            dateOfBirth,
            gender,
            phoneNumber
        } = req.body;

        // Check if the username, email, or phone number is already registered
        const existingUser = await User.findOne({ $or: [{ username }, { email }, { phoneNumber }] });
        if (existingUser) {
            return res.status(400).json({ message: 'Username, email, or phone number is already in use' });
        }

        const newUser = new User({
            username,
            email,
            password,
            fullName,
            dateOfBirth,
            gender,
            phoneNumber
        });

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);
        newUser.password = hashedPassword;

        await newUser.save();
        // Respond with success message
        res.status(201).json({ message: 'User registered successfully' });
    } catch (error) {
        console.error('Error in user signup:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
};

exports.getUserByRoleEmailAndPassword = async (req, res) => {
    const { email, password: userPassword } = req.body;
    try {
        // Find the user by email
        const user = await User.findOne({ email });

        // If user not found
        if (!user) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        // Compare passwords
        const isPasswordMatching = await user.comparePassword(userPassword);

        // If passwords don't match
        if (!isPasswordMatching) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        // Exclude the password field from the user object
        const { password, ...userWithoutPassword } = user.toObject();

        // If user and password match
        res.json(userWithoutPassword);
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
};

exports.getUserByPhone = async (req, res) => {
    try {
        const { phoneNumber } = req.body;
        const user = await User.findOne({ phoneNumber });
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        res.json(user);
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
};

exports.forgotPassword = async (req, res) => {
    try {
        const { email, newPassword, confirmPassword } = req.body;
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        const isOldPassword = await user.comparePassword(newPassword);
        if (isOldPassword) {
            res.json({ message: 'Please enter a password which is not the old one.' });
        }

        const arePasswordsSame = await user.arePasswordsSame(newPassword, confirmPassword);
        if (arePasswordsSame) {
            const validPassword = await user.validatePassword(newPassword);
            if (!validPassword) {
                return res.status(200).json({ message: 'Please provide a valid password' });
            }
            user.password = await user.hashedPassword(newPassword);
            await user.save();
            res.json({ message: 'Password updated successfully.' });
        }
        else {
            res.json({ message: 'Passwords do not match' });
        }
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
};

exports.checkUserByPhoneNumber = async (req, res) => {
    try {
        const { phoneNumber } = req.query;
        const user = await User.findOne({ phoneNumber });
        if (user) {
            return res.status(200).json({ exists: true, user });
        } else {
            return res.status(404).json({ exists: false });
        }
    } catch (error) {
        console.error('Error checking user by phone number:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
};
