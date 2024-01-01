const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const session = require('express-session');
const bodyParser = require('body-parser');
const cors = require('cors'); 

const app = express();
const port = 3000;

// Connect to MongoDB
mongoose.connect('mongodburl', { useNewUrlParser: true, useUnifiedTopology: true });

app.use(session({
  secret: 'your_session_secret', // replace with a secure secret
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false } // set to true if using HTTPS
}));

app.use(cors())

const userSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  password: { type: String, required: true }
});

const User = mongoose.model('User', userSchema);

app.use(bodyParser.json());

// Registration endpoint
app.post('/register', async (req, res) => {
  try {
    const { username, password } = req.body;

    // Check if both username and password are provided
    if (!username || !password) {
      return res.status(400).json({ error: 'Both username and password are required' });
    }

    // Hash the password before saving it to the database
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create a new user
    const newUser = new User({
      username,
      password: hashedPassword
    });

    // Save the user to the database
    await newUser.save();

    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal server error during registration' });
  }
});

// Login endpoint
app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    // Validate input
    if (!username || !password) {
      console.error('Validation failed: Both username and password are required');
      return res.status(400).json({ error: 'Both username and password are required' });
    }

    // Check if the user exists in the database
    const user = await User.findOne({ username });

    if (!user) {
      console.error(`User not found: ${username}`);
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    // Compare passwords
    const passwordMatch = await bcrypt.compare(password, user.password);

    if (!passwordMatch) {
      console.error(`Invalid password for user: ${username}`);
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    // Store user information in the session
    req.session.user = { username: user.username };

    // Respond with the authenticated user's username
    console.log(`User ${username} logged in successfully`);
    res.json({ username: user.username });
  } catch (error) {
    console.error('Internal server error during login:', error);
    res.status(500).json({ error: 'Internal server error during login' });
  }
});


// Logout endpoint
app.post('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error(err);
      res.status(500).json({ error: 'Internal server error during logout' });
    } else {
      res.json({ message: 'Logout successful' });
    }
  });
});

// Example home route that requires authentication
app.get('/home', (req, res) => {
  if (req.session.user) {
    res.send(`Welcome, ${req.session.user.username}!`);
  } else {
    res.status(401).send('Unauthorized');
  }
});

app.get('/all', async (req, res) => {
  try {
    const users = await User.find({}, { _id: 0, username: 1 }); // Exclude _id and include only the username
    res.json(users);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal server error while fetching users' });
  }
});

app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
