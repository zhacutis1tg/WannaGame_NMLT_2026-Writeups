const fs = require('fs');
const express = require('express');
const session = require('express-session');
const crypto = require('crypto');
const bodyParser = require('body-parser');
const passport = require('./auth');
const { addUser ,initAdminUser} = require('./users');
const { getTodosByUsername,addTodo} = require('./todo');

const app = express();
const FLAG = fs.readFileSync('flag.txt', 'utf8');
const BLACKLIST = "'\";--/*#=%()<>+,";


app.use(bodyParser.urlencoded({ extended: false }));

function wafBlockAdmin(req, res, next) {
  const { username } = req.body || {};
  if (typeof username === 'string') {
    const normalized = username.trim().toLowerCase();
    if (normalized === 'admin') {
      return res.status(403).send('Forbidden: Sorry we don\'t want to meet admin :)!');
    }
  }
  next();
}

app.use(session({
  secret: crypto.randomBytes(12).toString('hex'),
  resave: false,
  saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

app.get('/', (req, res) => {
  res.send(`
    <h1>Home</h1>
    ${req.user
      ? `<p>Logged in as ${req.user.username}</p>
         <a href="/todos/new">Create Todo</a><br/>
         <a href="/todos?username=${req.user.username}">View Todos</a><br/>
         <a href="/logout">Logout</a>`
      : `<a href="/login">Login</a>`}
  `);
});

app.get('/register', (req, res) => {
  res.send(`
    <form method="post" action="/register">
      <input name="username" placeholder="username" required />
      <input name="password" type="password" placeholder="password" required />
      <button>Register</button>
    </form>
  `);
});

app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).send('Missing username or password');
  }
  try {
    await addUser(username, password);
    return res.redirect('/login');
  } catch (err) {
    if (err.code === 'SQLITE_CONSTRAINT') {
      return res.status(409).send('Username already exists');
    }
    return res.status(500).send('Registration failed');
  }
});

app.get('/login', wafBlockAdmin, (req, res) => {
  res.send(`
    <form method="post" action="/login">
      <input name="username" placeholder="username" required />
      <input name="password" type="password" placeholder="password" required />
      <button>Login</button>
    </form>
  `);
});

app.post('/login', wafBlockAdmin, passport.authenticate('local', {
  successRedirect: '/',
  failureRedirect: '/login'
}));

app.get('/logout', (req, res) => {
  req.logout(() => {
    res.redirect('/');
  });
});

app.get('/profile', (req, res) => {
  if (!req.user) return res.redirect('/login');
  res.send(`<h1>Profile</h1><p>Welcome ${req.user.username}</p>`);
});

app.get('/todos', async (req, res) => {
  const { username } = req.query;
  if (!username || typeof username !== 'string' ) return res.status(400).send('Invalid username');
  let strLen = Array.from(username).length;
  // I failed dsa so linear search is peak
  for (let i = 0; i < strLen; i++) { 
    if (BLACKLIST.includes(username[i])) { 
      return res.status(400).send('What are you doing ? Your username is weird !');
    }
  }

  try {
    const todos = await getTodosByUsername(username);
    res.send(`
      <h1>Todos for ${username}</h1>
      <ul>
        ${todos.map(t => `<li>${t.title}</li>`).join('')}
      </ul>
      <a href="/">Home</a>
    `);
  } catch (err) {
    res.status(500).send('Error');
  }
});

app.get('/todos/new', (req, res) => {
  if (!req.user) return res.redirect('/login');
  res.send(`
    <form method="post" action="/todos">
      <input name="title" placeholder="todo title" required />
      <button>Create</button>
    </form>
  `);
});

app.post('/todos', async (req, res) => {
  if (!req.user) return res.redirect('/login');
  const { title } = req.body;
  if (!title) return res.status(400).send('Missing title');
  try {
    await addTodo(req.user.id, title);
    res.redirect('/');
  } catch (err) {
    res.status(500).send('Failed to create todo');
  }
});

app.get("/flag", (req, res) => {
  if (!req.user || req.user.username !== "admin") return  res.redirect('/login'); 
  const replacer = req.query.replacer || 'W1{redacted}'; 
  fs.readFile('flag.txt', 'utf8', (err, data) => {
  if (err) {
  return  res.status(400).send(err)
  }
  data = data.replace(FLAG,replacer)
  return res.send(data)
});
})

initAdminUser().then(admin => {
  if (admin) {
    console.log('Admin created');
    console.log('username:', admin.username);
    console.log('password:', admin.password);
  }
});
app.listen(3000, () => console.log('Server running on http://localhost:3000'));