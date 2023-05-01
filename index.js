require("./utils.js");

require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;

const port = process.env.PORT || 3000;

const app = express();

const Joi = require("joi");

const expireTime = 1 * 60 * 60 * 1000;

const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;

var { database } = include('databaseConnection');

const userCollection = database.db(mongodb_database).collection('users');

app.use(express.urlencoded({ extended: false }));

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
}
));

app.get('/nosql-injection', async (req, res) => {
    var username = req.query.user;

    if (!username) {
        res.send(`<h3>no user provided - try /nosql-injection?user=name</h3> <h3>or /nosql-injection?user[$ne]=name</h3>`);
        return;
    }
    console.log("user: " + username);

    const schema = Joi.string().max(20).required();  
    const validationResult = schema.validate(username);

    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.send("<h1 style='color:darkred;'>A NoSQL injection attack was detected!!</h1>");
        return;
    }

    const result = await userCollection.find({ username: username }).project({ username: 1, password: 1, _id: 1 }).toArray();

    console.log(result);

    res.send(`<h1>Hello ${username}</h1>`);
});

app.get('/', (req, res) => {
    if (!req.session.authenticated) {
        var html = `This is Emily's assignment 1 ! :D 
                    <div><a href="/signup">Sign Up</a></div>
                    <div><a href="/login">Log In</a></div>`;
        res.send(html);
        return;
    } else {
        var html = `Hello, ${req.session.username}!
                    <div><a href="/members">Members Page</a></div>
                    <div><a href="/signout">Sign Out</a></div>`;
        res.send(html);
    }
});

app.get('/signup', (req, res) => {
    var html = `
    Create user
    <form action='/submitUser' method='post'>
    <input name='username' type='text' placeholder='username'>
    <input name='email' type='email' placeholder='email'>
    <input name='password' type='password' placeholder='password'>
    <button>Submit</button>
    </form>
    `;
    res.send(html);
});

app.post('/submitUser', async (req, res) => {
    var username = req.body.username;
    var email = req.body.email;
    var password = req.body.password;

    if (!username || !email || !password) {
        var html = `<div>${!username ? 'Please provide a valid username.' : ''}<br>
                    ${!email ? 'Please provide a valid email.' : ''}<br>
                    ${!password ? 'Please provide a valid password.' : ''}</div>
                    <a href='/signup'>Go back</a>`;
        res.send(html);
        return;
    }

    const schema = Joi.object({
        username: Joi.string().alphanum().max(20).required(),
        email: Joi.string().email().max(100).required(),
        password: Joi.string().max(20).required()
    });

    const validationResult = schema.validate({ username, email, password });
    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.redirect("/signup");
        return;
    }

    var hashedPassword = await bcrypt.hash(password, saltRounds);

    await userCollection.insertOne({ username: username, email: email, password: hashedPassword });
    console.log("Inserted user");

    req.session.authenticated = true;
    req.session.username = username;
    req.session.cookie.maxAge = expireTime;

    res.redirect('/members');
});

app.get('/login', (req, res) => {
    var html = `Log in
                <form action='/loggingin' method='post'>
                <input name='email' type='email' placeholder='email'>
                <input name='password' type='password' placeholder='password'>
                <button>Submit</button>
                </form>`;
    res.send(html);
});

app.post('/loggingin', async (req, res) => {
    var username = req.body.username;
    var email = req.body.email;
    var password = req.body.password;

    if (!email || !password) {
        var html = `<div>
                    ${!email ? 'Please provide a valid email.' : ''}<br>
                    ${!password ? 'Please provide a valid password.' : ''}
                    </div>
                    <a href='/login'>Go back</a>`;
        res.send(html);
        return;
    }

    const schema = Joi.string().email().required(); 
    const validationResult = schema.validate(email);
    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.redirect("/login");
        return;
    }

    const result = await userCollection.find({ email: email }).project({ username: 1, email: 1, password: 1, _id: 1 }).toArray();   //then use them in  mongoDB

    console.log(result);

    if (result.length != 1) {
        var html = `<div>Invalid email/password combination.</div>
                    <br>
                    <a href='/login'>Go back</a>`;
        res.send(html);
        return;
    }
    if (await bcrypt.compare(password, result[0].password)) {
        console.log("correct password");
        req.session.authenticated = true;
        req.session.username = result[0].username;
        req.session.cookie.maxAge = expireTime;

        res.redirect('/members');
        return;
    }
    else {
        var html = `<div>Invalid email/password combination.</div>
                    <br>
                    <a href='/login'>Go back</a>`;
        res.send(html);
        return;
    }
});

app.get('/members', (req, res) => {
    if (!req.session.authenticated) {
        res.redirect('/');
    }
    var html = `Hello, ${req.session.username}!
                <br>
                <img src="${getRandomImage()}" style="width:500px;">
                <br>
                <div><a href="/signout">Sign Out</a></div>`;
    res.send(html);

    function getRandomImage() {
        const images = ['/sun.jpg', '/snow.jpg', '/lake.webp'];
        return images[Math.floor(Math.random() * images.length)];
      }
});

app.get('/signout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});


app.use(express.static(__dirname + "/public"));

app.get("*", (req, res) => { 
    res.status(404);
    res.send("Page not found - 404");
})

app.listen(port, () => {
    console.log("Node application listening on port " + port);
});