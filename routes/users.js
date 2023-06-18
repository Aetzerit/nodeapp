var express = require('express');
var router = express.Router();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');

// Sign up
router.post('/signup', [
  body('username').isEmail(),
  body('password').isLength({ min: 5 })
], async function(req, res) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    const hashedPassword = await bcrypt.hash(req.body.password, 10)
    const user = { username: req.body.username, password: hashedPassword }
    // save the user in the database here

    res.status(201).json({ message: "User created" });
  } catch {
    res.status(500).json({ message: "Error creating user" });
  }
});

// Log in
router.post('/login', [
  body('username').not().isEmpty().withMessage('Username is required'),
  body('password').not().isEmpty().withMessage('Password is required')
], async function(req, res) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  // get the user from the database here
  const user = getUserFromDb(req.body.username);

  if (user == null) {
    return res.status(400).json({ message: 'Cannot find user' })
  }
  try {
    if(await bcrypt.compare(req.body.password, user.password)) {
      const accessToken = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET)
      res.json({ accessToken: accessToken })
    } else {
      res.status(401).json({ message: 'Not Allowed' })
    }
  } catch {
    res.status(500).json({ message: 'Error logging in user' });
  }
});

module.exports = router;
