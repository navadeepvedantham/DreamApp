const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true
  },
  email: {
    type: String,
    required: true,
    unique: true,
    validate: {
      validator: function(v) {
        return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);
      },
      message: props => `${props.value} is not a valid email address!`
    }
  },
  password: {
    type: String,
    required: true
  },
  fullName: {
    type: String,
    required: true
  },
  dateOfBirth: {
    type: Date,
    required: true
  },
  gender: {
    type: String,
    enum: ['Male', 'Female', 'Other'],
    required: true
  }
});

// Method to compare passwords
userSchema.methods.comparePassword = async function(candidatePassword) {
    try {
        return await bcrypt.compare(candidatePassword, this.password);
    } catch (err) {
        return err.message;
    }
};

// Method to validate password complexity
userSchema.methods.validatePassword = function validatePassword(password) {
  // Minimum length requirement
  if (password.length < 8) {
    throw new Error("Password must be at least 8 characters long.");
  }
  // Complexity check
  const complexityRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]+$/;
  if (!complexityRegex.test(password)) {
    throw new Error("Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character.");
  }

  // Avoidance of common patterns (optional)
  const commonPatterns = [
      '123456', 'password', '12345678', 'qwerty', '12345', '123456789', 
      'football', '1234', '1234567', 'baseball', 'welcome', '1234567890', 
      'abc123', '111111', '1qaz2wsx', 'dragon', 'master', 'monkey', 
      'letmein', 'login', 'princess', 'qwertyuiop', 'solo', 'passw0rd'
  ];
  if (commonPatterns.includes(password.toLowerCase())) {
    throw new Error("Password is too common.");
  }
  return true;
}

// Method to hash password
userSchema.methods.hashedPassword = async function hashedPassword(password){
  const saltRounds = 10;
  const salt = await bcrypt.genSalt(saltRounds);

  // Hash the password using the salt
  const hashedPassword = await bcrypt.hash(password, salt);
  return hashedPassword;
}

// Method to check if passwords match
userSchema.methods.arePasswordsSame = async function arePasswordsSame(newPassword, confirmPassword){
  try {
    return newPassword === confirmPassword;
  } catch (err) {
    throw new Error(err);
  }
}

const User = mongoose.model('User', userSchema);

module.exports = User;
