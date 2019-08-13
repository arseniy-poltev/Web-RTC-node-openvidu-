/* CONFIGURATION */

var OpenVidu = require('openvidu-node-client').OpenVidu;
var Session = require('openvidu-node-client').Session;
var OpenViduRole = require('openvidu-node-client').OpenViduRole;
var TokenOptions = require('openvidu-node-client').TokenOptions;

// Check launch arguments: must receive openvidu-server URL and the secret
if (process.argv.length != 4) {
    console.log("Usage: node " + __filename + " OPENVIDU_URL OPENVIDU_SECRET");
    process.exit(-1);
}
// For demo purposes we ignore self-signed certificate
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

// Node imports
var express = require('express');
var fs = require('fs');
var session = require('express-session');
var https = require('https');
var bodyParser = require('body-parser'); // Pull information from HTML POST (express4)
var app = express(); // Create our app with express



// Server configuration
app.use(session({
    saveUninitialized: true,
    resave: false,
    secret: 'MY_SECRET'
}));
app.use(express.static(__dirname + '/public')); // Set the static files location
app.use(bodyParser.urlencoded({
    'extended': 'true'
})); // Parse application/x-www-form-urlencoded
app.use(bodyParser.json()); // Parse application/json
app.use(bodyParser.json({
    type: 'application/vnd.api+json'
})); // Parse application/vnd.api+json as json
app.set('view engine', 'ejs'); // Embedded JavaScript as template engine

// Listen (start app with node server.js)
var options = {
    key: fs.readFileSync('openvidukey.pem'),
    cert: fs.readFileSync('openviducert.pem')
};
// https.createServer(options, app).listen(5000);
https.createServer(options, app).listen(443);

// Mock database

const model_users=require('./models/users');


// Environment variable: URL where our OpenVidu server is listening
var OPENVIDU_URL = process.argv[2];
// Environment variable: secret shared with our OpenVidu server
var OPENVIDU_SECRET = process.argv[3];

// Entrypoint to OpenVidu Node Client SDK
var OV = new OpenVidu(OPENVIDU_URL, OPENVIDU_SECRET);

// Collection to pair session names with OpenVidu Session objects
var mapSessions = {};
// Collection to pair session names with tokens
var mapSessionNamesTokens = {};

// console.log("App listening on port 5000");
console.log("App listening on port 443");

//One-Time Password library
var SMSGH = require('smsghjs');

/* CONFIGURATION */
/////////////////****  Global Variables   ****/////////////////////

// confirm code for One-Time Password

var global_OTP_code;//several digits code

//incorrect username and password==>>>message

var message_user_error="";

// in the previous time, logged in user

var old_user;

//login info buffer

var logger="";
var logging_pass="";
/////////////////////////////////////////////////////////////////////

/* REST API */

app.post('/', loginController);
app.get('/', loginController);

function loginController(req, res) {
    if (req.session.loggedUser) { // User is logged
        old_user = req.session.loggedUser;
        res.redirect('/dashboard');
    } else { // User is not logged
        logger="";
        logging_pass="";
        req.session.destroy();
        res.render('index.ejs',{
            message_user_error:message_user_error
        });
    }
}

app.post('/logout', (req, res) => {
    logger="";
    logging_pass="";
    req.session.destroy();
    res.redirect('/');
});

app.get('/auth',authController);
app.post('/auth',authController);

function authController(req,res){
// Check if the user is already logged in
    if (isLogged(req.session)) {
        // User is already logged. Immediately return dashboard
        var user = req.session.loggedUser;
        res.render('dashboard.ejs', {
            user: user.username
        });
    } else {
        // User wasn't logged and wants to

        var user;
        var pass;
        if (logger === "" && logging_pass === "") {
            // Retrieve params from POST body
            user = req.body.user;
            logger=user;
            pass = req.body.pass;
            logging_pass=pass;
            console.log('new login');
        }else {
            user=logger;
            pass=logging_pass;
            console.log('old login');

        }

        console.log("Logging in | {user, pass}={" + user + ", " + pass + "}");

        model_users.login(user,pass,function (err, count) {
            if(err) {
                console.log(err+"^^^^^^^^^^^^^^^^^^^>>>>>>>>>>>err");
            } else{
                if (count !=null && count[0]!=null && count[0].userid>0){
                    console.log("count="+count[0].userid +"'^^^^^^^^^^^^^>>>>>>>>>>>success");

                     // Correct user-pass
                    // Validate session and return OK
                    // Value stored in req.session allows us to identify the user in future requests
                    console.log("\n'" + user + "' has logged in");


                    // get phone number
                    var phone_num=count[0].phonenum;

                    console.log('\n^^^^^^^^^^phone number===>'+phone_num);

                    // One-Time Password messaging

                    // get `clientId` and `clientSecret` from SMSGH
                    // `topupApiKey` is optional
                    // `uspToken` is optional
                    var sms  = new SMSGH({
                        clientId: "lsvmowhl",
                        clientSecret: "jmxuzjzl",
                    });

                    sms.setContextPath('v3');

                    global_OTP_code=getOTP();

                    console.log('\ngenerating scheduled message^^^^^^^^^^^^^OTP code===>'+global_OTP_code);

                    // Send a quick message
                    sms.messaging.sendQuickMessage(
                        'ConnectWork',
                        phone_num,
                        global_OTP_code+' is your one-time security code.',

                        function (err, smres) {
                            if (err) {  // handle the Error
                                console.log("^^^^^^^^^^^response error===>" + err + ">>>>res>>>" + smres);
                                res.redirect('/');
                            } else {                            // do something with the response
                                console.log('send message_response^^^^^^^^^^^^' + smres);
                                old_user = count[0];
                                message_user_error = "";
                                res.render('auth.ejs');
                            }
                        }
                    );


                }else{
                    console.log("count="+count[0] +"^^^^^^^^^^^^^^^^>>>>>>>>>>>no result");
                    // Wrong user-pass
                    req.session.destroy();
                    logger="";
                    logging_pass="";
                    message_user_error="username and password are incorrect";
                    res.redirect('/');
                }
            }
        });
    }
}

app.post('/dashboard', dashboardController);
app.get('/dashboard', dashboardController);

function dashboardController(req, res) {

    // Check if the user is already logged in
    if (isLogged(req.session)) {
        // User is already logged. Immediately return dashboard
        var user = req.session.loggedUser;
        res.render('dashboard.ejs', {
            user: user.username
        });
    } else {

        // Retrieve params from POST body
        var code = req.body.confirm_code;


        if (code===global_OTP_code) { // Correct code

            req.session.loggedUser = old_user;
            res.render('dashboard.ejs', {
                user: old_user.username
            });

        } else { // Wrong code
            console.log('code error^^^^^^^^^^^^'+code);
            res.redirect('/');
        }
    }
}

app.post('/session', (req, res) => {
    if (!isLogged(req.session)) {
        logger="";
        logging_pass="";
        req.session.destroy();
        res.redirect('/');
    } else {
        // The nickname sent by the client
        var clientData = req.body.data;
        // The video-call to connect
        var sessionName = req.body.sessionname;

        // Role associated to this user
        var role;
        switch (old_user.roles) {
            case 1:
                role=OpenViduRole.PUBLISHER;
                break;
            case 2:
                role=OpenViduRole.SUBSCRIBER;
        }

        // Optional data to be passed to other users when this user connects to the video-call
        // In this case, a JSON with the value we stored in the req.session object on login
        var serverData = JSON.stringify({ serverData: req.session.loggedUser.username });

        console.log("Getting a token | {sessionName}={" + sessionName + "}"+"old_user.role>>"+role);

        // Build tokenOptions object with the serverData and the role
        var tokenOptions = {
            data: serverData,
            role: role
        };
        console.log("\n>>>tokenOptions: serverData->"+serverData+" , role->"+role);

        if (mapSessions[sessionName]) {
            // Session already exists
            console.log('Existing session ' + sessionName);

            // Get the existing Session from the collection
            var mySession = mapSessions[sessionName];

            // Generate a new token asynchronously with the recently created tokenOptions
            mySession.generateToken(tokenOptions)
                .then(token => {

                    // Store the new token in the collection of tokens
                    mapSessionNamesTokens[sessionName].push(token);

                    // Return session template with all the needed attributes
                    res.render('session.ejs', {
                        sessionId: mySession.getSessionId(),
                        token: token,
                        nickName: clientData,
                        userName: req.session.loggedUser.username,
                        sessionName: sessionName,
                        role:role
                    });
                })
                .catch(error => {
                    console.error(error);
                });
        } else {
            // New session
            console.log('New session ' + sessionName);

            // Create a new OpenVidu Session asynchronously
            OV.createSession()
                .then(session => {
                    // Store the new Session in the collection of Sessions
                    mapSessions[sessionName] = session;
                    // Store a new empty array in the collection of tokens
                    mapSessionNamesTokens[sessionName] = [];

                    // Generate a new token asynchronously with the recently created tokenOptions
                    session.generateToken(tokenOptions)
                        .then(token => {

                            // Store the new token in the collection of tokens
                            mapSessionNamesTokens[sessionName].push(token);

                            // Return session template with all the needed attributes
                            res.render('session.ejs', {
                                sessionName: sessionName,
                                token: token,
                                nickName: clientData,
                                userName: req.session.loggedUser.username,
                                role:role
                            });
                        })
                        .catch(error => {
                            console.error(error);
                        });
                })
                .catch(error => {
                    console.error(error);
                });
        }
    }
});

app.post('/leave-session', (req, res) => {
    if (!isLogged(req.session)) {
        logger="";
        logging_pass="";
        req.session.destroy();
        res.render('index.ejs');
    } else {
        // Retrieve params from POST body
        var sessionName = req.body.sessionname;
        var token = req.body.token;
        console.log('Removing user | {sessionName, token}={' + sessionName + ', ' + token + '}');

        // If the session exists
        if (mapSessions[sessionName] && mapSessionNamesTokens[sessionName]) {
            var tokens = mapSessionNamesTokens[sessionName];
            var index = tokens.indexOf(token);

            // If the token exists
            if (index !== -1) {
                // Token removed
                tokens.splice(index, 1);
                console.log(sessionName + ': ' + tokens.toString());
            } else {
                var msg = 'Problems in the app server: the TOKEN wasn\'t valid';
                console.log(msg);
                res.redirect('/dashboard');
            }
            if (tokens.length == 0) {
                // Last user left: session must be removed
                console.log(sessionName + ' empty!');
                delete mapSessions[sessionName];
            }
            res.redirect('/dashboard');
        } else {
            var msg = 'Problems in the app server: the SESSION does not exist';
            console.log(msg);
            res.status(500).send(msg);
        }
    }
});

/* REST API */



/* AUXILIARY METHODS */


function isLogged(session) {
    return (session.loggedUser != null);
}

function getBasicAuth() {
    return 'Basic ' + (new Buffer('OPENVIDUAPP:' + OPENVIDU_SECRET).toString('base64'));
}

function getOTP() {
    const normalUpperString="ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const normalNumber="0123456789";

    var result_str="";
    var result_num="";

    for(var i=0;i<4;i++){
        result_str+=normalUpperString.charAt(Math.floor(Math.random()*26));
        result_num+=normalNumber.charAt(Math.floor(Math.random()*10));
    }

    return result_str+"-"+result_num;

}

/* AUXILIARY METHODS */
