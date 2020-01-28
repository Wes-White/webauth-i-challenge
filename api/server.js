const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const session = require('express-session');

const Users = require('../helpers/user-helper');

const server = express();

const sessionConfig = {
  name: 'web-auth', //rename to acvoid default sid
  secret: process.env.COOKIE_SECRET || 'keep it safe', //for encryption
  cookie: {
    maxAge: 1000 * 30, //how long will be valid in milliseconds
    secure: false, //can I send without https (should be true in production)
    httpOnly: true //meaning cookie cannot be accessed by js
  },
  resave: false, //do we want to recreate session even if it has not changed
  saveUninitialized: false // GDPR compliance  cannot set cookies automatically.
};

server.use(express.json());
server.use(helmet());
server.use(cors());
server.use(session(sessionConfig));

server.get('/', (req, res) => {
  res.send('<h1> WeB AuTh<h1>');
});

//GET ALL USERS

server.get('/api/users', restricted, async (req, res) => {
  try {
    const users = await Users.find();
    if (users) {
      res.status(200).json(users);
    } else {
      res
        .status(400)
        .json({ message: 'Bad request. We are unablet to get the users.' });
    }
  } catch (err) {
    res
      .status(500)
      .json({ message: 'Something went wrong with this request.', error: err });
  }
});

//REGISTER

server.post('/api/register', (req, res) => {
  let user = req.body;
  const hash = bcrypt.hashSync(user.password, 10);
  user.password = hash;

  Users.add(user)
    .then(newUser => {
      res.status(201).json(newUser);
    })
    .catch(error => {
      res.status(500).json({
        message: 'Something went wrong with this request.',
        error: error
      });
    });
});

//LOGIN

server.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    Users.find(username)
      .first()
      .then(user => {
        if (!user || !bcrypt.compareSync(password, user.password)) {
          return res
            .status(401)
            .json({ message: 'Ivaild username and password combination.' });
        } else {
          req.session.user = user;
          res.status(200).json({ message: `Hello, ${username}!!! ` });
        }
      });
  } catch (err) {
    res
      .status(500)
      .json({ message: 'Something went wrong with your request.', error: err });
  }
});

//LOGOUT

server.get('/logout', restricted, (req, res) => {
  if (req.session) {
    req.session.destroy(err => {
      if (err) {
        res
          .status(500)
          .json({ message: 'There was an error with your request.' });
      } else {
        res.status(200).json({ message: `GoodBye, ${username}!!! ` });
      }
    });
  } else {
    res.status(200).json({ messge: 'You were not logged in to begain with.' });
  }
});

module.exports = server;

function restricted(req, res, next) {
  if (req.session && req.session.username) {
    next();
  } else {
    res.status(401).json({ message: 'You shall not pass.' });
  }
}
