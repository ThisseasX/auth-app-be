import cors from 'cors';
import bodyParser from 'body-parser';
import cookieParser from 'cookie-parser';
import express from 'express';
import jwt from 'jsonwebtoken';
import passport from 'passport';
import JwtCookieComboStrategy from 'passport-jwt-cookiecombo';
import { Strategy as LocalStrategy } from 'passport-local';

const SECRET = 's0m3s3cr3t';

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
      done(null, { username, password });
    }),
  );

const corsOptions = {
  origin: 'http://localhost:3000',
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
      sameSite: true,
      signed: true,
      secure: true,
    });

    res.json({ token });
  })
  .get(
    '/logout',
    passport.authenticate('jwt-cookiecombo', { session: false }),
    (req, res) => {
      console.log(req.logout()); // clears req.user
      res.clearCookie('authToken'); // clears the cookie
      res.send('logged out');
    },
  )
  .get(
    '/',
    passport.authenticate('jwt-cookiecombo', { session: false }),
    (req, res) => {
      res.cookie('unsigned-cookie', '123');

      console.log(req.cookies);
      console.log(req.signedCookies);
      console.log(req.user);
      console.log(req.isAuthenticated());

      res.send('hello');
    },
  )
  .listen(4000);
