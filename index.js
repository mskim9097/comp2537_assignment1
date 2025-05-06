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

const expireTime = 60 * 60 * 1000;

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
    if(!req.session.authenticated) {
        res.send(`
            <button onclick="location.href='/signup'">Sign up</button>
            <br>
            <button onclick="location.href='/login'">Log in</button>
            `);
    } else {
        res.send(`
            Hello, ${req.session.name}!<br>
            <button onclick="location.href='/members'">
                Go to Members Area
            </button>
            <br>
            <button onclick="location.href='/logout'">Logout</button>
            `);
    }
    
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
        var html = '';

        if(name == "") {
            html += 'Name is required.<br>';
        }
        if(email == "") {
            html += 'Email is required.<br>';
        }
        if(password == "") {
            html += 'Password is required.<br>';
        }
        if (html == '') {
            html += 'Name, email, or password is not in a valid format.<br>';
        }
        html += `<br><a href="/signup">Try again</a>`;

        res.send(html);
        return;
    }
    var hashedPassword = await bcrypt.hash(password, saltRounds);

    await userCollection.insertOne({name: name, email: email, password: hashedPassword});

    req.session.authenticated = true;
	req.session.name = name;
	req.session.cookie.maxAge = expireTime;

    res.redirect("/members");
});

app.get('/login', (req, res) => {
    res.send(`
        log in
        <form action='/loginSubmit' method='post'>
            <input name='email' type='email' placeholder='email'/><br>
            <input name='password' type='password' placeholder='password'/><br>
            <button>Submit</button>
        </form>
        `);
});

app.post('/loginSubmit', async (req, res) => {
    var email = req.body.email;
    var password = req.body.password;

    const schema = Joi.object(
		{
			email: Joi.string().email().max(30).required(),
            password: Joi.string().max(20).required()
		});
    const validationResult = schema.validate({email, password});
    if (validationResult.error != null) {
        res.send(`
            Email or password is not in a valid format.<br><br>
            <a href="/login">Try again</a>
            `);
        return;
    }

    const result = await userCollection.find({email: email}).project({email: 1, name: 1, password: 1, _id: 1}).toArray();

    if (result.length == 1 && await bcrypt.compare(password, result[0].password)) {
        const name = result[0].name;
		req.session.authenticated = true;
		req.session.name = name;
		req.session.cookie.maxAge = expireTime;

		res.redirect('/members');
		return;
	} else {
		res.send(`
            Invalid email/password combination.<br><br>
            <a href="/login">Try again</a>
            `);
		return;
	}
});

app.get('/members', (req, res) => {
    if(!req.session.authenticated) {
        res.redirect('/');
        return;
    }
    var images = ['cat1.jpg', 'cat2.jpg', 'cat3.jpg'];
    var randomImage = images[Math.floor(Math.random() * images.length)];
    res.send(`
        <h1>Hello, ${req.session.name}.</h1>
        <img src="/${randomImage}" alt="Random Cat" width="300" height="200"><br>
        <button onclick="location.href='/logout'">Sign out</button>
        `);
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});

app.use(express.static(__dirname + "/public"));

app.get(/.*/, (req,res) => {
	res.status(404);
	res.send("Page not found - 404");
})

app.listen(port, () => {
	console.log("Node application listening on port "+ port);
}); 