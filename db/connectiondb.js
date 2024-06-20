const mongoose = require('mongoose');
require('dotenv').config()

async function ConnectDb() {
    try{
        await mongoose.connect(process.env.URL_CONNECT)
        console.log('Connect on Mongo Db ')
    }catch{
        console.log('error', Error)
    }
};

ConnectDb();
