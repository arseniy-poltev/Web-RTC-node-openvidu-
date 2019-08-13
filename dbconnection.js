const mysql = require('mysql');
const connection=mysql.createPool({
    // host:'localhost',
    host:'35.197.253.179',
    database:'trogj',
    user:'root',
    password:'qu5emc2E4O7IF7CJ'
    // password:'qqqqqq'
});
// connection.connect(function(err){
//     if(!err) {
//         console.log("Database is connected ... \n\n");
//     } else {
//         console.log("Error connecting database ... \n\n");
//     }
// });
module.exports=connection;