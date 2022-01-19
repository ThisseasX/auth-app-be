import cors from 'cors';
import bodyParser from 'body-parser';
import cookieParser from 'cookie-parser';
import express from 'express';
import jwt from 'jsonwebtoken';
import passport from 'passport';
import JwtCookieComboStrategy from 'passport-jwt-cookiecombo';
import { Strategy as LocalStrategy } from 'passport-local';

const SECRET = process.env.SECRET || 's0m3s3cr3t';
const PORT = process.env.PORT || 4000;
const ORIGIN = process.env.ORIGIN || 'http://localhost:3000';

passport
  .use(
    new JwtCookieComboStrategy(
      {
        secretOrPublicKey: SECRET,
        jwtCookieName: 'authToken',
      },
      (payload, done) => {
        return done(null, payload.user);
      },
    ),
  )
  .use(
    new LocalStrategy((username, password, done) => {
      if (username === 'a' && password === 'a') {
        // simulate user not found
        done(null, false);
      } else {
        // simulate user found
        done(null, { username, password });
      }
    }),
  );

const corsOptions = {
  origin: ORIGIN,
  credentials: true,
};

const app = express();

app
  .use(cors(corsOptions))
  .use(cookieParser(SECRET))
  .use(bodyParser.json())
  .use(passport.initialize())
  .post('/login', passport.authenticate('local', { session: false }), (req, res) => {
    const user = req.user;

    // Create auth token
    const token = jwt.sign({ user }, SECRET);

    // Set the cookie
    res.cookie('authToken', token, {
      httpOnly: true, // only visible to the server (not document.cookie)
      sameSite: 'None',
      signed: true,
      secure: true,
    });

    res.json({ user });
  })
  // Authenticate all further routes
  .use(passport.authenticate('jwt-cookiecombo', { session: false }))
  .post('/verifyToken', (req, res) => {
    const { authToken } = req.signedCookies;
    const user = jwt.verify(authToken, SECRET);
    res.json(user);
  })
  .get('/logout', (req, res) => {
    req.logout(); // clears req.user
    res.clearCookie('authToken'); // clears the cookie
    res.send('logged out');
  })
  .get('/', (req, res) => {
    res.cookie('unsigned-cookie', '123');

    console.log(req.cookies);
    console.log(req.signedCookies);
    console.log(req.user);
    console.log(req.isAuthenticated());

    res.send('hello');
  })
  .listen(PORT);
