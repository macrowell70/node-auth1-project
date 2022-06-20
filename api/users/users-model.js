const db = require('../../data/db-config');

/**
  resolves to an ARRAY with all users, each user having { user_id, username }
 */
function find() {
  return db('users')
}

/**
  resolves to an ARRAY with all users that match the filter condition
 */
function findBy(filter) {

}

/**
  resolves to the user { user_id, username } with the given user_id
 */
async function findById(user_id) {
  const user = await db('users').where({ user_id }).first();
  return {
    user_id: user.user_id,
    username: user.username
  }
}

/**
  resolves to the newly inserted user { user_id, username }
 */
async function add(user) {
  const [user_id] = await db('users').insert(user)
  return findById(user_id)
}

// Don't forget to add these to the `exports` object so they can be required in other modules
module.exports = {
  find,
  findBy,
  findById,
  add
}