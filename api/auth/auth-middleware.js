const Users = require('../users/users-model');
const bcrypt = require('bcryptjs');

/*
  If the user does not have a session saved in the server

  status 401
  {
    "message": "You shall not pass!"
  }
*/
function restricted(req, res, next) {
  const { username, password } = req.body
}

/*
  If the username in req.body already exists in the database

  status 422
  {
    "message": "Username taken"
  }
*/
async function checkUsernameFree(req, res, next) {
  try {
    let { username } = req.body
    const user = await Users.findBy({ username })
    if (user.length != 0 ) {
      next({ status: 422, message: "Username already exists" })
    }
    if (user.length == 0) {
      next()
    }
  } catch (err) {
    next(err)
  }
}

/*
  If the username in req.body does NOT exist in the database

  status 401
  {
    "message": "Invalid credentials"
  }
*/
function checkUsernameExists(req, res, next) {
  let { username } = req.body
  Users.findBy({ username })
    .then(user => {
      if(!user) { next({ status: 401, message: "Invalid credentials" }) }
      next()
    })
    .catch(err => next(err.message))
}

/*
  If password is missing from req.body, or if it's 3 chars or shorter

  status 422
  {
    "message": "Password must be longer than 3 chars"
  }
*/
function checkPasswordLength(req, res, next) {
  const credentials = req.body
  if (!credentials.password || credentials.password.length <= 3) {
    next({ status: 422, message: "Password must be longer than 3 chars" })
  }
  const hash = bcrypt.hashSync(credentials.password, 14)
  credentials.password = hash
  next()
}

// Don't forget to add these to the `exports` object so they can be required in other modules
module.exports = {
  restricted,
  checkUsernameFree,
  checkUsernameExists,
  checkPasswordLength
}