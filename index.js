require("./utils.js");
require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;

const app = express();
const port = process.env.PORT || 3000;
const Joi = require("joi");

const expireTime = 24 * 60 * 60 * 1000;

const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;

var {database} = include('databaseConnection');

const userCollection = database.db(mongodb_database).collection('users');

app.use(express.urlencoded({extended: false}));

var mongoStore = MongoStore.create({
	mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
	crypto: {
		secret: mongodb_session_secret
	}
})

app.use(session({ 
    secret: node_session_secret,
    store: mongoStore, 
    saveUninitialized: false, 
    resave: true
}));

app.get('/', (req, res) => {
    res.send(`
        <button onclick="location.href='/signup'">Sign up</button>
        <br>
        <button onclick="location.href='/login'">Log in</button>
        `);
});

app.get('/signup', (req, res) => {
    res.send(`
        create user
        <form action='/signupSubmit' method='post'>
            <input name='name' type='text' placeholder='name'/><br>
            <input name='email' type='email' placeholder='email'/><br>
            <input name='password' type='password' placeholder='password'/><br>
            <button>Submit</button>
        </form>
        `);
});
app.post('/signupSubmit', async (req, res) => {
    var name = req.body.name;
    var email = req.body.email;
    var password = req.body.password;

    const schema = Joi.object({
        name: Joi.string().alphanum().max(20).required(),
        email: Joi.string().email().max(30).required(),
        password: Joi.string().max(20).required()
    });
    const validationResult = schema.validate({name, email, password});

    if (validationResult.error != null) {
        res.send(`
            Invalid email/password combination.<br><br>
            <a href="/signup">Try again</a>
            `);
    }
    var hashedPassword = await bcrypt.hash(password, saltRounds);

    await userCollection.insertOne({name: name, email: email, password: hashedPassword});

    res.redirect("/members");
});
app.get('/login', (req, res) => {
    res.send('login page');
});
app.get('/members', (req, res) => {
    res.send('members page');
});
app.get('/logout', (req, res) => {
    
});

app.use(express.static(__dirname + "/public"));

app.get(/.*/, (req,res) => {
	res.status(404);
	res.send("Page not found - 404");
})

app.listen(port, () => {
	console.log("Node application listening on port "+ port);
}); 