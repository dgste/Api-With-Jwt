require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const app = express();
require('./db/connectiondb');

// Config Json Response 
app.use(express.json())

// Open Route
app.get('/', (req, res) => {
    res.status(200).json({msg: 'success', message: 'the api is working'})
});

// Models
const User = require('./models/User')

// Register User
app.post('/auth/register', async (req, res) => {
    const { name, email, password, confirmpass } = req.body;

    if (!name) {
        return res.status(422).json({msg: 'the name is mandatory'});
    }
    if (!email) {
        return res.status(422).json({msg: 'the email is mandatory'});
    }
    if (!password) {
        return res.status(422).json({msg: 'the password is mandatory'});
    }
    if (password !== confirmpass) {
        return res.status(422).json({msg: 'the passwords do not match'});
    }

    // Additional logic to handle user registration
    // Example:
    // const userExists = await User.findOne({ email });
    // if (userExists) {
    //     return res.status(422).json({msg: 'User already exists'});
    // }

    // const salt = await bcrypt.genSalt(10);
    // const passwordHash = await bcrypt.hash(password, salt);
    // const user = new User({ name, email, password: passwordHash });

    // try {
    //     await user.save();
    //     res.status(201).json({ msg: 'User created successfully' });
    // } catch (err) {
    //     res.status(500).json({ msg: 'Error registering user' });
    // }
});

app.listen(3000, () => {
    console.log('Server is running on port 3000');
});
