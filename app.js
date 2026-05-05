// =============================
// FULL STACK APP (MongoDB + Roles + Dashboard)
// Run:
// npm init -y
// npm install express mongoose jsonwebtoken cors dotenv
// Create .env file:
// MONGO_URI=your_mongodb_uri
// JWT_SECRET=secret123
// Then: node app.js
// =============================

require('dotenv').config();
const express = require("express");
const mongoose = require("mongoose");
const jwt = require("jsonwebtoken");
const cors = require("cors");

const app = express();
app.use(express.json());
app.use(cors());

// ================= DB =================
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB Connected"))
  .catch(err => console.log(err));

// ================= MODELS =================
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true }
});

const projectSchema = new mongoose.Schema({
  name: { type: String, required: true },
  admin: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  members: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }]
});

const taskSchema = new mongoose.Schema({
  title: { type: String, required: true },
  status: {
    type: String,
    enum: ["todo", "inprogress", "done"],
    default: "todo"
  },
  project: { type: mongoose.Schema.Types.ObjectId, ref: "Project", required: true },
  assignedTo: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  dueDate: { type: Date }
});

const User = mongoose.model("User", userSchema);
const Project = mongoose.model("Project", projectSchema);
const Task = mongoose.model("Task", taskSchema);

// ================= AUTH =================
function auth(req, res, next) {
  const token = req.headers.authorization;
  if (!token) return res.status(403).send("No token");
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    res.status(401).send("Invalid token");
  }
}

app.post("/signup", async (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password) {
    return res.status(400).send("All fields required");
  }

  const exists = await User.findOne({ email });
  if (exists) return res.status(400).send("User already exists");

  const user = await User.create({ name, email, password });
  res.json(user);
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  const user = await User.findOne({ email });
  if (!user || user.password !== password) {
    return res.status(401).send("Invalid credentials");
  }

  const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET);
  res.json({ token });
});

// ================= PROJECT =================
app.post("/projects", auth, async (req, res) => {
  const project = await Project.create({
    name: req.body.name,
    admin: req.user.id,
    members: [req.user.id]
  });
  res.json(project);
});

app.get("/projects", auth, async (req, res) => {
  const projects = await Project.find({ members: req.user.id });
  res.json(projects);
});

app.put("/tasks/:id", auth, async (req, res) => {
  const task = await Task.findById(req.params.id);

  if (task.assignedTo.toString() !== req.user.id) {
    return res.status(403).send("Not authorized");
  }

  task.status = req.body.status;
  await task.save();

  res.json(task);
});
app.get("/tasks/:projectId", auth, async (req, res) => {
  const project = await Project.findById(req.params.projectId);

  if (!project.members.includes(req.user.id)) {
    return res.status(403).send("Access denied");
  }

  const tasks = await Task.find({ project: req.params.projectId });
  res.json(tasks);
});

app.post("/projects/:id/add", auth, async (req, res) => {
  const project = await Project.findById(req.params.id);

  if (project.admin.toString() !== req.user.id) {
    return res.status(403).send("Only admin can add members");
  }

  if (!project.members.includes(req.body.userId)) {
    project.members.push(req.body.userId);
  }

  await project.save();
  res.json(project);
});

// ================= TASK =================
app.post("/tasks", auth, async (req, res) => {
  const { title, project, assignedTo } = req.body;

  if (!title || !project || !assignedTo) {
    return res.status(400).send("Missing fields");
  }

  const proj = await Project.findById(project);

  if (!proj.members.includes(assignedTo)) {
    return res.status(400).send("User not in project");
  }

  if (proj.admin.toString() !== req.user.id) {
    return res.status(403).send("Only admin can create task");
  }

  const task = await Task.create(req.body);
  res.json(task);
});

app.get("/tasks/:projectId", auth, async (req, res) => {
  const project = await Project.findById(req.params.projectId);

  if (!project.members.includes(req.user.id)) {
    return res.status(403).send("Access denied");
  }

  const tasks = await Task.find({ project: req.params.projectId });
  res.json(tasks);
});

app.put("/tasks/:id", auth, async (req, res) => {
  const task = await Task.findById(req.params.id);

  if (task.assignedTo.toString() !== req.user.id) {
    return res.status(403).send("Not authorized");
  }

  task.status = req.body.status;
  await task.save();

  res.json(task);
});
app.post("/projects/:id/add", auth, async (req, res) => {
  const project = await Project.findById(req.params.id);

  if (project.admin.toString() !== req.user.id) {
    return res.status(403).send("Only admin can add members");
  }

  if (!project.members.includes(req.body.userId)) {
    project.members.push(req.body.userId);
  }

  await project.save();
  res.json(project);
});

// ================= DASHBOARD =================
app.get("/dashboard", auth, async (req, res) => {
  const total = await Task.countDocuments({ assignedTo: req.user.id });

  const byStatus = await Task.aggregate([
    { $match: { assignedTo: mongoose.Types.ObjectId(req.user.id) } },
    { $group: { _id: "$status", count: { $sum: 1 } } }
  ]);

  const overdue = await Task.find({
    assignedTo: req.user.id,
    dueDate: { $lt: new Date() },
    status: { $ne: "done" }
  });

  res.json({ total, byStatus, overdue });
});

// ================= FRONTEND =================
app.get("/", (req, res) => {
  res.send(`
  <html>
  <body>
    <h2>Login</h2>
    <input id="email" placeholder="Email" />
    <input id="password" placeholder="Password" />
    <button onclick="login()">Login</button>

    <h2>Create Project</h2>
    <input id="project" />
    <button onclick="createProject()">Create</button>

    <h2>Dashboard</h2>
    <button onclick="loadDashboard()">Load</button>
    <pre id="dash"></pre>

    <script>
      let token="";

      async function login(){
        const res=await fetch('/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email:email.value,password:password.value})});
        const data=await res.json(); token=data.token;
      }

      async function createProject(){
        await fetch('/projects',{method:'POST',headers:{'Content-Type':'application/json','Authorization':token},body:JSON.stringify({name:project.value})});
      }

      async function loadDashboard(){
        const res=await fetch('/dashboard',{headers:{'Authorization':token}});
        const data=await res.json();
        dash.innerText=JSON.stringify(data,null,2);
      }
    </script>
  </body>
  </html>
  `);
});

// ================= START =================
app.listen(5000, () => console.log("Server running on http://localhost:5000"));