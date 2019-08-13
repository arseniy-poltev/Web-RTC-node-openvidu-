const db=require('./../dbconnection');
const crypto=require('crypto');

const users={
    login:function (username,password,callback) {
        return db.query("SELECT * FROM users WHERE username=? AND password=?",
            [username,crypto.createHash('sha256').update(password).digest('base64')],callback);
    }
};
module.exports=users;