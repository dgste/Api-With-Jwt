require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const app = express();
require('./db/connectiondb');

// Config Json Response 
app.use(express.json());

// Open Route
app.get('/', (req, res) => {
    res.status(200).json({ msg: 'success', message: 'the api is working' });
});

//Private Route
app.get('/user/:id', async (req, res) => {
    const user = await User.findById({
        id: req.params._id
    })
    
})

// Models
const User = require('./models/User');

// Register User
app.post('/auth/register', async (req, res) => {
    const { name, email, password, confirmpass } = req.body;

    if (!name) {
        return res.status(422).json({ msg: 'the name is mandatory' });
    }
    if (!email) {
        return res.status(422).json({ msg: 'the email is mandatory' });
    }
    if (!password) {
        return res.status(422).json({ msg: 'the password is mandatory' });
    }
    if (password !== confirmpass) {
        return res.status(422).json({ msg: 'the passwords do not match' });
    }

    // Check if user exists
    const userExists = await User.findOne({ email });
    if (userExists) {
        return res.status(422).json({ msg: 'User already exists' });
    }

    // Create password hash
    const salt = await bcrypt.genSalt(12);
    const passwordHash = await bcrypt.hash(password, salt);

    // Create user
    const user = new User({
        name,
        email,
        password: passwordHash
    });

    try {
        await user.save();
        return res.status(201).json({ msg: 'User created successfully' });
    } catch (err) {
        console.error(err);
        return res.status(500).json({ msg: 'Server error, try again later' });
    }
});

// Authenticate User
app.post('/auth/user', async (req, res) => {
    const { email, password } = req.body;

    // Validations
    if (!email) {
        return res.status(422).json({ msg: 'the email is mandatory' });
    }
    if (!password) {
        return res.status(422).json({ msg: 'the password is mandatory' });
    }

    // Check if user exists
    const user = await User.findOne({ email });
    if (!user) {
        return res.status(422).json({ msg: 'user not found' });
    }

    // Check if password matches
    const checkPassword = await bcrypt.compare(password, user.password);
    if (!checkPassword) {
        return res.status(404).json({ msg: 'password invalid' });
    }

    try {
        const secret = process.env.SECRET;
        const token = jwt.sign({
            id: user._id
        }, secret);
        return res.status(200).json({ msg: 'authentication was successful', token });
    } catch (err) {
        console.error(err);
        return res.status(500).json({ msg: 'Server error, try again later' });
    }
});

app.listen(3000, () => {
    console.log('Server is running on port 3000');
});
