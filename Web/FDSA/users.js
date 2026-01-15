const crypto = require('crypto');
const db = require('./db');

async function addUser(username, password) {
  return new Promise((resolve, reject) => {
    db.run(
      'INSERT INTO users (username, password) VALUES (?, ?)',
      [username, password],
      function (err) {
        if (err) return reject(err);
        resolve({ id: this.lastID, username, password });
      }
    );
  });
}



function findUserByUsername(username) {
  return new Promise((resolve, reject) => {
    db.get(
      `SELECT * FROM users WHERE username = ?`,
      [username],
      (err, row) => err ? reject(err) : resolve(row)
    );
  });
}

function findUserById(id) {
  return new Promise((resolve, reject) => {
    db.get(
      `SELECT * FROM users WHERE id = ?`,
      [id],
      (err, row) => err ? reject(err) : resolve(row)
    );
  });
}

async function initAdminUser() {
  const password = crypto.randomBytes(12).toString('hex');

  return new Promise((resolve, reject) => {
    db.run(
      'INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)',
      ['admin', password],
      function (err) {
        if (err) return reject(err);
        if (this.changes === 0) return resolve(null);

        resolve({
          id: this.lastID,
          username: 'admin',
          password
        });
      }
    );
  });
}


module.exports = {
  addUser,
  findUserByUsername,
  findUserById,
  initAdminUser
};
