import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy } from "passport-local";
import session from "express-session";
import env from "dotenv";

const app = express();
const port = 3000;
const saltRounds = 10;

env.config();

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use(session({ secret: process.env.SESSION_SECRET, resave: false, saveUninitialized: true }));
app.use(passport.initialize());
app.use(passport.session());
app.set("view engine", "ejs");

// Database connection
const db = new pg.Client({
  user: process.env.PG_USER,
  host: process.env.PG_HOST,
  database: process.env.PG_DATABASE,
  password: process.env.PG_PASSWORD,
  port: process.env.PG_PORT,
});
db.connect();

// Passport Configuration
passport.use(
  new Strategy({ usernameField: "email" }, async (email, password, done) => {
    try {
      const result = await db.query("SELECT * FROM users WHERE email = $1", [email]);
      if (result.rows.length > 0) {
        const user = result.rows[0];
        const match = await bcrypt.compare(password, user.password);
        if (match) return done(null, user);
      }
      return done(null, false, { message: "Invalid email or password" });
    } catch (err) {
      return done(err);
    }
  })
);

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  try {
    const result = await db.query("SELECT * FROM users WHERE id = $1", [id]);
    done(null, result.rows[0]);
  } catch (err) {
    done(err);
  }
});

// Middleware for authentication
function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) return next();
  res.redirect("/login");
}

// Routes
app.get("/", (req, res) => res.render("home"));
app.get("/register", (req, res) => res.render("register"));
app.get("/login", (req, res) => res.render("login"));
app.get("/tasks", ensureAuthenticated, async (req, res) => {
  try {
    const result = await db.query("SELECT * FROM tasks WHERE user_id = $1", [
      req.user.id,
    ]);
    const tasks = result.rows;
    res.render("tasks.ejs", {
      tasks: tasks,
       // Assuming the username is stored in the email
    });
  } catch (err) {
    console.error(err);
    res.status(500).send("Error fetching tasks");
  }
});

// Register a user
app.post("/register", async (req, res) => {
  const { username, email, password } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    await db.query("INSERT INTO users (username, email, password) VALUES ($1, $2, $3)", [
      username,
      email,
      hashedPassword,
    ]);
    res.redirect("/login");
  } catch (err) {
    console.error(err);
    res.status(500).send("Error registering user");
  }
});

// Login
app.post("/login", passport.authenticate("local", { successRedirect: "/tasks", failureRedirect: "/login" }));

// Logout
app.get("/logout", (req, res) => {
  req.logout(() => res.redirect("/"));
});

// Create a task
app.post("/tasks", ensureAuthenticated, async (req, res) => {
  const { title, description } = req.body;
  await db.query("INSERT INTO tasks (user_id, title, description) VALUES ($1, $2, $3)", [
    req.user.id,
    title,
    description,
  ]);
  res.redirect("/tasks");
});

// Update a task
app.post("/tasks/:id/update", ensureAuthenticated, async (req, res) => {
  const { id } = req.params;
  const { title, description } = req.body;
  await db.query("UPDATE tasks SET title = $1, description = $2 WHERE id = $3 AND user_id = $4", [
    title,
    description,
    id,
    req.user.id,
  ]);
  res.redirect("/tasks");
});

// Delete a task
app.post("/tasks/:id/delete", ensureAuthenticated, async (req, res) => {
  const { id } = req.params;
  await db.query("DELETE FROM tasks WHERE id = $1 AND user_id = $2", [id, req.user.id]);
  res.redirect("/tasks");
});

// Start the server
app.listen(port, () => console.log(`Server running on http://localhost:${port}`));
