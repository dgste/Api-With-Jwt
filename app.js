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

    //Check If User Existing
    const userExists = await User.findOne({ email: email });
    
    if(userExists){
        return res.status(422).json({msg: 'User already exists'});
    }

    //Create Password
    const salt = await bcrypt.genSalt(12)
    const passwordHash = await bcrypt.hash(password, salt)

    //Create User 
    const user = new User ({
        name, email, password: passwordHash
    });

    try{
        user.save()
        res.status(201).json({msg: "user created successfully"})

    }catch(Error){
        console.log(err)
        return res.status(500).json({msg: 'Not Found, Try Again Later'});
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

app.post('/auth/user', async (req, res) => {
    const { email, password } = req.body

    //validations
    if (!email) {
        return res.status(422).json({msg: 'the email is mandatory'});
    }
    if (!password) {
        return res.status(422).json({msg: 'the password is mandatory'});
    }

    //check if user existing
    const user = await User.findOne({ email: email });
    if(!user){
        return res.status(422).json({msg: 'user not found'});
    }

    //check if password match 
    const checkPassword = bcrypt.compare(password, user.password)
    if(!checkPassword){
        return res.status(404).json({msg: 'password invalid'});
    }
  
});

app.listen(3000, () => {
    console.log('Server is running on port 3000');
});
