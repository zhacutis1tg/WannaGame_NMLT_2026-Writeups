const db = require('./db');

function getTodosByUsername(username) {
  return new Promise((resolve, reject) => {
    const sql = `
      SELECT todos.*
      FROM todos
      JOIN users ON users.id = todos.user_id
      WHERE users.username = '${username}'
    `;

    db.all(sql, (err, rows) => {
      if (err) reject(err);
      else resolve(rows);
    });
  });
}

function addTodo(userId, title) {
  return new Promise((resolve, reject) => {
    db.run(
      `INSERT INTO todos (user_id, title) VALUES (?, ?)`,
      [userId, title],
      err => err ? reject(err) : resolve()
    );
  });
}

function deleteTodo(id) {
  return new Promise((resolve, reject) => {
    db.run(
      `DELETE FROM todos WHERE id = ?`,
      [id],
      err => err ? reject(err) : resolve()
    );
  });
}

module.exports = {
  getTodosByUsername,
  addTodo,
  deleteTodo,
};
