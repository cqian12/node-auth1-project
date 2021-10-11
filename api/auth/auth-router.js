// Require `checkUsernameFree`, `checkUsernameExists` and `checkPasswordLength`
// middleware functions from `auth-middleware.js`. You will need them here!
const express = require('express')
const bcrypt = require('bcryptjs')
const Users = require('./../users/users-model')
const { checkPasswordLength, checkUsernameExists, checkUsernameFree } = require('./auth-middleware')
const router = express.Router()

/**
  1 [POST] /api/auth/register { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "user_id": 2,
    "username": "sue"
  }

  response on username taken:
  status 422
  {
    "message": "Username taken"
  }

  response on password three chars or less:
  status 422
  {
    "message": "Password must be longer than 3 chars"
  }
 */
router.post('/register', checkUsernameFree, checkPasswordLength, async (req, res, next) => {
  try {
    const { username, password } = req.body
    const hash = bcrypt.hashSync(password, 8) 
    const user = await Users.add({username, password: hash})

    res.status(200).json(user)
  } catch(err) {
    next(err)
  }
})

/**
  2 [POST] /api/auth/login { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "message": "Welcome sue!"
  }

  response on invalid credentials:
  status 401
  {
    "message": "Invalid credentials"
  }
 */

router.post('/login', checkPasswordLength, checkUsernameExists, async (req, res, next) => {
  try {
    const { username, password } = req.body
    const [existingUser] = await Users.findBy({ username })

    if (existingUser && bcrypt.compareSync(password, existingUser.password)) {
      req.session.user = existingUser
      res.status(200).json({message: `Welcome ${existingUser.username}!`})
    } else {
      res.status(401).json({message:'Invalid credentials'})
    }
  } catch(err) {
    next(err)
  }
})

/**
  3 [GET] /api/auth/logout

  response for logged-in users:
  status 200
  {
    "message": "logged out"
  }

  response for not-logged-in users:
  status 200
  {
    "message": "no session"
  }
 */

router.get('/logout', (req, res ) => {
  if (req.session.user) {
    req.session.destroy(err => {
      if (err) {
        res.json({
          message: 'logout issue'
        })
      } else {
        res.status(200).json({ message: 'logged out'})
      }
    })
  } else {
    res.status(200).json({ message: 'no session' })
  }
})
 
// Don't forget to add the router to the `exports` object so it can be required in other modules
module.exports = router