// Follow this article
// https://blog.logrocket.com/implementing-two-factor-authentication-using-speakeasy/
const express = require('express');
const speakeasy = require('speakeasy');
// generate random user ids (universal unique identifier )
const uuid = require('uuid');
const { JsonDB } = require('node-json-db');
const { Config } = require('node-json-db/dist/lib/JsonDBConfig');

const app = express();
app.use(express.json());

// config takes arguments = (nameOfDB, saveDataOnPush, makeItHumanReadableOrNot, DataseparatedBy)
const db = new JsonDB(new Config('myDatabase', true, false, '/'));

app.get('/api', (req,res) => {
    res.json({
        message: 'Welcome to the 2FA auth',
    })
});

// Register user & create a temp secret
app.post('/api/register', (req,res) => {
    // generate id using version4 of uuid
    const id = uuid.v4();

    try{
        const path = `/users/${id}`;
        // generate temporary secret
        // the generated secret is actually a object
        // this object consists of ascii, hex, base32(we will use base32) and otpauth_url(used for QRcode genration on frontend)
        const temp_secret = speakeasy.generateSecret();

        db.push(path, { id, temp_secret });
        res.json({ id, secret: temp_secret.base32 });
    }catch(err){
        console.log(err);
        res.status(500).json({message: 'Error generating the secret',});
    }
});

// verify token and make secret
app.post("/api/verify", (req,res) => {
  const { userId, token } = req.body;
  try {
    // Retrieve user from database
    const path = `/users/${userId}`;
    const user = db.getData(path);
    console.log({ user });

    const { base32: secret } = user.temp_secret;
    // verify is a function that checks tokens and return boolean
    const verified = speakeasy.totp.verify({
      secret,
      encoding: 'base32',
      token
    });

    if (verified) {
      // Update user data
      db.push(path, { id: userId, secret: user.temp_secret });
      res.json({ verified: true })
    } else {
      res.json({ verified: false})
    }
  } catch(error) {
    console.error(error);
    res.status(500).json({ message: 'Error retrieving user'})
  };
});

// Validate user
app.post("/api/validate", (req,res) => {
    const { userId, token } = req.body;
    try {
      // Retrieve user from database
      const path = `/users/${userId}`;
      const user = db.getData(path);
      console.log({ user })

      const { base32: secret } = user.secret;

      // Returns true if the token matches
      const tokenValidates = speakeasy.totp.verify({
        secret,
        encoding: 'base32',
        token,
        window: 1
      });

      if (tokenValidates) {
        res.json({ validated: true })
      } else {
        res.json({ validated: false})
      }
    } catch(error) {
      console.error(error);
      res.status(500).json({ message: 'Error retrieving user'})
    };
  })

const port = 3000 || process.env.PORT;

app.listen(port, ()=> console.log(`server listening at ${port}`));