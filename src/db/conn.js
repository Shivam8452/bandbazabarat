const mongoose = require("mongoose");
require('dotenv').config();
mongoose.connect(process.env.Mongo_URL || process.env.Local_URL ,{
    // useCreateIndex:true,
    // useNewParser:true,
    useUnifiedTopology:true
}).then(()=>{
    console.log("connection successful");
}).catch((error) => {
    console.log(error);
})