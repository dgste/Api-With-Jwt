const mongoose = require('mongoose');
const {Schema} = mongoose;
const User = mongoose.model('User', {
    name: String,
    email: String,
    password: String
});

module.exports = User