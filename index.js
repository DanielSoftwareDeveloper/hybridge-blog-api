// Cargar variables de entorno
require("dotenv").config();

// Imports
const express = require("express");
const cors = require("cors");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const { Strategy: JwtStrategy, ExtractJwt } = require("passport-jwt");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");

const { sequelize, Post, Author, User } = require("./models");

// Inicializar Express
const app = express();
app.use(cors());
app.use(express.json());
app.use(passport.initialize());

// Test de conexión a DB
sequelize
  .authenticate()
  .then(() => console.log("Conectado a la DB"))
  .catch((err) => console.error("No se pudo conectar a la DB:", err));

// Ruta de salud para confirmar que la API está activa
app.get("/", (req, res) => {
  res.json({
    message: "Hybridge Blog API",
    author: "Daniel Reyes",
    endpoints:
      "/api/signup, /api/login, /api/profile, /api/authors, /api/posts",
  });
});

/* ------------------------------------------
   1. ESTRATEGIA LOCAL (LOGIN)
------------------------------------------- */
passport.use(
  "local",
  new LocalStrategy(
    { usernameField: "email", passwordField: "password", session: false },
    async (email, password, done) => {
      try {
        const user = await User.findOne({ where: { email } });
        if (!user) return done(null, false, { message: "Usuario no existe" });

        const ok = await bcrypt.compare(password, user.password);
        if (!ok) return done(null, false, { message: "Contraseña incorrecta" });

        return done(null, user);
      } catch (err) {
        return done(err);
      }
    }
  )
);

/* ------------------------------------------
   2. ESTRATEGIA JWT (PROTECCIÓN)
------------------------------------------- */
passport.use(
  "jwt",
  new JwtStrategy(
    {
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: process.env.JWT_SECRET,
      session: false,
    },
    async (payload, done) => {
      try {
        const user = await User.findByPk(payload.id);
        if (!user) return done(null, false);
        return done(null, user);
      } catch (err) {
        return done(err, false);
      }
    }
  )
);

/* ------------------------------------------
   3. RUTAS DE AUTENTICACIÓN
------------------------------------------- */

// REGISTRO
app.post("/api/signup", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    const hash = await bcrypt.hash(password, 10);

    const user = await User.create({
      name,
      email,
      password: hash,
    });

    res.status(201).json({
      id: user.id,
      email: user.email,
    });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

// LOGIN → genera token
app.post(
  "/api/login",
  passport.authenticate("local", { session: false }),
  (req, res) => {
    const payload = { id: req.user.id };
    const token = jwt.sign(payload, process.env.JWT_SECRET, {
      expiresIn: "1h",
    });

    res.json({ token, token_type: "Bearer" });
  }
);

// Ruta protegida
app.get(
  "/api/profile",
  passport.authenticate("jwt", { session: false }),
  (req, res) => {
    res.json({
      id: req.user.id,
      email: req.user.email,
      msg: "Acceso concedido 👋",
    });
  }
);

/* ------------------------------------------
   4. CRUD AUTORES
------------------------------------------- */

// CREATE
app.post("/api/authors", async (req, res) => {
  const { name } = req.body;
  const author = await Author.create({ name });
  res.status(201).json(author);
});

// READ ALL
app.get("/api/authors", async (req, res) => {
  const authors = await Author.findAll();
  res.json(authors);
});

// READ ONE
app.get("/api/authors/:id", async (req, res) => {
  const author = await Author.findByPk(req.params.id);
  if (!author) return res.status(404).json({ error: "Autor no encontrado" });
  res.json(author);
});

// UPDATE
app.patch("/api/authors/:id", async (req, res) => {
  const author = await Author.findByPk(req.params.id);
  if (!author) return res.status(404).json({ error: "Autor no encontrado" });

  if (req.body.name !== undefined) author.name = req.body.name;

  await author.save();
  res.json(author);
});

// DELETE
app.delete("/api/authors/:id", async (req, res) => {
  const author = await Author.findByPk(req.params.id);
  if (!author) return res.status(404).json({ error: "Autor no encontrado" });

  await author.destroy();
  res.json({ message: "Autor eliminado correctamente" });
});

/* ------------------------------------------
   5. CRUD PUBLICACIONES
------------------------------------------- */
app.post("/api/posts", async (req, res) => {
  const post = await Post.create(req.body);
  res.status(201).json(post);
});

app.get("/api/posts", async (req, res) => {
  res.json(await Post.findAll());
});

app.get("/api/posts/:id", async (req, res) => {
  const post = await Post.findByPk(req.params.id);
  if (!post)
    return res.status(404).json({ error: "Publicación no encontrada" });
  res.json(post);
});

app.patch("/api/posts/:id", async (req, res) => {
  const post = await Post.findByPk(req.params.id);
  if (!post)
    return res.status(404).json({ error: "Publicación no encontrada" });

  await post.update(req.body);
  res.json(post);
});

app.delete("/api/posts/:id", async (req, res) => {
  const post = await Post.findByPk(req.params.id);
  if (!post)
    return res.status(404).json({ error: "Publicación no encontrada" });

  await post.destroy();
  res.json({ message: "Publicación eliminada correctamente" });
});

// Servidor
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Servidor escuchando en puerto ${PORT}`));
