var express = require('express');
var bodyParser = require('body-parser');
var jwt = require("jsonwebtoken");
var cookieParser = require('cookie-parser')

var app = express();
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json())
app.use(cookieParser())


//sample users repository
const users = [
  {
    name: "Akshay Galande",
    password: "samplepass",
    email: "mybytecode@gmail.com"
  },
  {
    name: "mybytecode",
    password: "samplepass",
    email: "sample@gmail.com"
  }
];

//secret key
const SECRET_KEY = "samplekey"

app.get("/", function (req, res, next) {
  res.status(200).json({ message: "Hello" })
})

app.post('/register', function (req, res) {
  try {
    const { email, userName, password } = req.body;

    if (users.find(user => user.email == email)) {
      throw new Error("User with same email already exists.");
    }

    const newUser = {
      name: userName,
      email: email,
      password: password
    };
    users.push(newUser);

    //create a payload to add in JWT and indetify user in future.
    const payload = { email: email, role: 'user' };

    //create a JWT token using payload
    const token = createToken(payload);

    //create a httponly cookie so only server side javascript can access it. It will add security layer in implementation
    const cookie = createCookie(token, 'Authorization', true);

    //Do not return user password
    delete newUser.password;

    res.setHeader('Set-Cookie', [cookie]);
    res.status(200).json({ data: newUser, message: 'registration success' });
  } catch (e) {
    res.status(400).json({ data: null, message: e.message })
  }
});


app.post('/login', function (req, res) {
  try {
    const { email, password } = req.body;

    const user = users.find(user => user.email == email);
    if (!user) {
      throw new Error("Email not registered.")
    }

    if (user.password !== password) {
      throw new Error("Wrong password entered.")
    }

    //if everything goes well, create a token and setup a session.
    //create a payload to add in JWT and indetify user in future.
    const payload = { email: email, role: 'user' };

    //create a JWT token using payload
    const token = createToken(payload);

    //create a httponly cookie so only server side javascript can access it. It will add security layer in implementation
    const cookie = createCookie(token, 'Authorization', true);

    //Do not return user password
    delete user.password;

    res.setHeader('Set-Cookie', [cookie]);
    res.status(200).json({ data: user, message: 'login success' });
  } catch (e) {
    res.status(200).json({ error: e.message })
  }
});

app.post('/logout', function () {
  //unset the httponly auth cookie
  res.setHeader('Set-Cookie', ['Authorization=; Max-age=0']);
  res.status(200).json({ data: null, message: 'logout' });
})


app.post('/me', authMiddlewear, function (req, res, next) {
  try {
    const user = req.user;
    res.status(200).json({ data: user, message: "Current User" })
  } catch (e) {
    res.status(400).json({ error: e.message })
  }
})

function createToken(payload) {
  return jwt.sign(payload, SECRET_KEY, { expiresIn: 60 * 60 * 24 * 30 }); //access token will expire in 30 days
}

function createCookie(token, name, httpOnly = null) {
  return `${name}=${token}; ${httpOnly ? 'HttpOnly' : null}; Max-Age=${60 * 60 * 24 * 30};`;
}

async function authMiddlewear(req, res, next) {
  try {

    const Authorization = req.cookies['Authorization'] || null;
    if (Authorization) {
      const verificationResponse = (await jwt.verify(Authorization, SECRET_KEY));
      const user = users.find(user => user.email == verificationResponse.email);
      if (user) {
        req.user = user;
        next();
      } else {
        res.status(401).json({ error: "Wrong authentication token" })
      }
    } else {
      res.status(404).json({ error: "Token missing" })
    }
  } catch (error) {

    res.status(401).json({ error: "Wrong authentication token" })
  }
}



//server config
var port = 9000;
app.listen(port);
console.log('Server started! At http://localhost:' + port);
