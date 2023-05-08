require("./utils.js");

require('dotenv').config();
const url = require('url');
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');

const { ObjectId } = require('mongodb');

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

app.set('view engine', 'ejs');

const navLinks = [
    {name: "Home", link: "/"},
    {name: "Login", link: "/login"},
    {name: "Members", link: "/members"},
    {name: "Admin", link: "/admin"},
    {name: "404", link: "/dne"},
    {name: "Signout", link: "/signout"}
]

app.use("/", (req,res,next) => {
    app.locals.navLinks = navLinks;
    app.locals.currentURL = url.parse(req.url).pathname;
    next();
});

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
}));

function isValidSession(req) {
    return req.session.authenticated;
}

function sessionValidation(req, res, next) {
    if (isValidSession(req)) {
        next();
    }
    else {
        res.redirect('/login');
    }
}

function isAdmin(req) {
    return req.session.user_type == 'admin';
}

function adminAuthorization(req, res, next) {
    if (!isAdmin(req)) {
        res.status(403);
        res.render("errorMessage", {error: "Sorry! Not Authorized."});
        return;
    }
    else {
        next();
    }
}

app.get('/', (req, res) => {
    res.render("index", { authenticated: req.session.authenticated, username: req.session.username });
});

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

app.get('/signup', (req, res) => {
    res.render("signup");
});


app.post('/submitUser', async (req, res) => {
    var username = req.body.username;
    var email = req.body.email;
    var password = req.body.password;

    if (!username || !email || !password) {
        res.render('submitUser', {username, email, password});
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

    await userCollection.insertOne({ username: username, email: email, password: hashedPassword, user_type: "user" });
    console.log("Inserted user");

    req.session.authenticated = true;
    req.session.username = username;
    req.session.cookie.maxAge = expireTime;

    res.redirect('/members');
});

app.get('/login', (req, res) => {
    res.render("login");
});

app.post('/loggingin', async (req, res) => {
    var username = req.body.username;
    var email = req.body.email;
    var password = req.body.password;

    if (!email || !password) {
        res.render('loggingin', {email, password});
        return;
    }

    const schema = Joi.string().email().required();
    const validationResult = schema.validate(email);
    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.redirect("/login");
        return;
    }

    const result = await userCollection.find({ email: email }).project({ username: 1, email: 1, password: 1, user_type: 1,  _id: 1 }).toArray(); 
    console.log(result);

    if (result.length != 1) {
        res.render('logginginInvalid')
        return;
    }
    if (await bcrypt.compare(password, result[0].password)) {
        console.log("correct password");
        req.session.authenticated = true;
        req.session.username = result[0].username;
        req.session.user_type = result[0].user_type;
        req.session.cookie.maxAge = expireTime;

        res.redirect('/members');
        return;
    }
    else {
        res.render('logginginInvalid')
        return;
    }
});

app.get('/signout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});

// = loggedin page in demo
app.get('/members', (req, res) => {
    if (!req.session.authenticated) {
        res.redirect('/');
    }

    res.render('members', {username: req.session.username});
});


app.get('/admin',  sessionValidation, adminAuthorization, async (req,res) => {
    const result = await userCollection.find().project({username: 1, user_type: 1, _id: 1}).toArray();
    console.log(result);
    res.render("admin", {users: result});
});

app.post('/admin/promote/:id', sessionValidation, adminAuthorization, async (req, res) => {
    const userId = req.params.id;
    await userCollection.updateOne({ _id: ObjectId(userId) }, { $set: { user_type: 'admin' } });
    res.redirect('/admin');
});
  
app.post('/admin/demote/:id', sessionValidation, adminAuthorization, async (req, res) => {
    const userId = req.params.id;
    await userCollection.updateOne({ _id: ObjectId(userId) }, { $set: { user_type: 'user' } });
    res.redirect('/admin');
});



app.use(express.static(__dirname + "/public"));

app.get("*", (req, res) => {
    res.status(404);
    res.render("404");
})

app.listen(port, () => {
    console.log("Node application listening on port " + port);
});
