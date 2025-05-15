
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


const expireTime = 24 * 60 * 60 * 1000; //expires after 1 day  (hours * minutes * seconds * millis)

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

var {database} = include('databaseConnection');

const userCollection = database.db(mongodb_database).collection('users');

app.set('view engine', 'ejs');

app.use(express.urlencoded({extended: false}));

var mongoStore = MongoStore.create({
	mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
	crypto: {
		secret: mongodb_session_secret
	}
})

app.use(session({ 
    secret: node_session_secret,
	store: mongoStore, //default is memory store 
	saveUninitialized: false, 
	resave: true
}
));

function isValidSession(req) {
    if (req.session.authenticated) {
        return true;
    }
    return false;
}

function sessionValidation(req,res,next) {
    if (isValidSession(req)) {
        next();
    }
    else {
        res.redirect('/login');
    }
}


function isAdmin(req) {
    if (req.session.user_type == 'admin') {
        return true;
    }
    return false;
}

function adminAuthorization(req, res, next) {
    if (!isAdmin(req)) {
        res.status(403);
        res.render("errorMessage", {error: "Not Authorized"});
        return;
    }
    else {
        next();
    }
}

app.get('/', (req,res) => {
    res.render("index", { session: req.session });
});

app.get('/nosql-injection', async (req,res) => {
	var username = req.query.user;

	if (!username) {
		res.send(`<h3>no user provided - try /nosql-injection?user=name</h3> <h3>or /nosql-injection?user[$ne]=name</h3>`);
		return;
	}
	console.log("user: "+username);

	const schema = Joi.string().max(20).required();
	const validationResult = schema.validate(username);

	//If we didn't use Joi to validate and check for a valid URL parameter below
	// we could run our userCollection.find and it would be possible to attack.
	// A URL parameter of user[$ne]=name would get executed as a MongoDB command
	// and may result in revealing information about all users or a successful
	// login without knowing the correct password.
	if (validationResult.error != null) {  
	   console.log(validationResult.error);
	   res.send("<h1 style='color:darkred;'>A NoSQL injection attack was detected!!</h1>");
	   return;
	}	

	const result = await userCollection.find({username: username}).project({username: 1, password: 1, _id: 1}).toArray();

	console.log(result);

    res.send(`<h1>Hello ${username}</h1>`);
});

app.get('/about', (req, res) => {
  res.render('about', {
    session: req.session
  });
});

app.get('/contact', (req, res) => {
  const missingEmail = req.query.missing === '1';
  res.render("contact", { session: req.session, missing: missingEmail });
});

app.post('/submitEmail', (req, res) => {
  const email = req.body.email;
  if (!email || email.trim() === '') {
    return res.redirect('/contact?missing=1');
  }

  res.render("submitEmail", {
    session: req.session,
    email
  });
});

app.get('/createUser', (req,res) => {
    res.render("createUser");
});



app.get('/login', (req, res) => {
  res.render('login', { session: req.session, error: null });
});

app.post('/submitUser', async (req, res) => {
  const schema = Joi.object({
    username: Joi.string().min(1).required().label('Name'),
    email: Joi.string().email().required().label('email address'),
    password: Joi.string().min(1).required().label('Password'),
  });

  const { error, value } = schema.validate(req.body);

  if (error) {
    const field = error.details[0].context.label;
    const message = field === 'email address'
      ? `Please provide an ${field}.`
      : `${field} is required.`;

    return res.render('signup', {
      error: message,
      session: req.session
    });
  }

  const { username, email, password } = value;
  const hashedPassword = await bcrypt.hash(password, 10);
  const userCollection = database.db("assignment2").collection("users");

  await userCollection.insertOne({
    username,
    email,
    password: hashedPassword
  });

  req.session.authenticated = true;
  req.session.username = username;

  res.redirect('/members');
});

app.post('/loginSubmit', async (req, res) => {
  const schema = Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().min(1).required()
  });

  const { error, value } = schema.validate(req.body);
  if (error) {
    return res.render('login', {
      error: 'Invalid input.',
      session: req.session
    });
  }

  const { email, password } = value;
  const userCollection = database.db("assignment2").collection("users");
  const user = await userCollection.findOne({ email });

  if (!user) {
    return res.render('login', {
      error: 'Invalid email/password combination.',
      session: req.session
    });
  }

  const passwordMatch = await bcrypt.compare(password, user.password);
  if (!passwordMatch) {
    return res.render('login', {
      error: 'Invalid email/password combination.',
      session: req.session
    });
  }

  req.session.authenticated = true;
  req.session.username = user.username;
  res.redirect('/members');
});

app.post('/loggingin', async (req,res) => {
    var username = req.body.username;
    var password = req.body.password;

	const schema = Joi.string().max(20).required();
	const validationResult = schema.validate(username);
	if (validationResult.error != null) {
	   console.log(validationResult.error);
	   res.redirect("/login");
	   return;
	}

	const result = await userCollection.find({username: username}).project({username: 1, password: 1, user_type: 1, _id: 1}).toArray();

	console.log(result);
	if (result.length != 1) {
		console.log("user not found");
		res.redirect("/login");
		return;
	}
	if (await bcrypt.compare(password, result[0].password)) {
		console.log("correct password");
		req.session.authenticated = true;
		req.session.username = username;
        req.session.user_type = result[0].user_type;
		req.session.cookie.maxAge = expireTime;

		res.redirect('/loggedIn');
		return;
	}
	else {
		console.log("incorrect password");
		res.redirect("/login");
		return;
	}
});

app.use('/loggedin', sessionValidation);
app.get('/loggedin', (req,res) => {
    if (!req.session.authenticated) {
        res.redirect('/login');
    }
    res.render("loggedin", { name: req.session.username });
});

app.get('/loggedin/info', (req,res) => {
    res.render("loggedin-info");
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});


app.get('/cat/:id', (req,res) => {
    var cat = req.params.id;

    res.render("cat", {cat: cat});
});

app.get('/signup', (req, res) => {
  res.render('signup', { session: req.session, error: null });
});

app.get('/admin', sessionValidation, adminAuthorization, async (req,res) => {
    const result = await userCollection.find().project({ username: 1, user_type: 1, _id: 1 }).toArray();
    res.render("admin", { users: result, session: req.session });
});

app.post('/promote', sessionValidation, adminAuthorization, async (req, res) => {
    const username = req.body.username;
    await userCollection.updateOne({ username }, { $set: { user_type: 'admin' } });
    res.redirect('/admin');
});

app.post('/demote', sessionValidation, adminAuthorization, async (req, res) => {
    const username = req.body.username;
    await userCollection.updateOne({ username }, { $set: { user_type: 'user' } });
    res.redirect('/admin');
});

app.get('/members', (req, res) => {
  if (!req.session.authenticated) {
    return res.redirect('/login');
  }

  res.render('loggedin', {
    session: req.session,
    name: req.session.username
  });
});

app.use(express.static("public"));

app.use(express.static(__dirname + "/public"));

app.get("*", (req,res) => {
	res.status(404);
	res.render("404");
})

app.listen(port, () => {
	console.log("Node application listening on port "+port);
}); 