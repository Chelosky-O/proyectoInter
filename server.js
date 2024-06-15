const express = require("express");
const session = require("express-session");
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const mysql = require("mysql2/promise");
const path = require("path");

const app = express();

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.use(express.static(path.join(__dirname, "public")));
// Configura la base de datos
let db;

function createDbPool() {
  db = mysql.createPool({
    host: "localhost",
    user: "root",
    password: "1234",
    //password: "password1234",
    database: "notas",
    port: 3307,
    //port: 3306,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
  });

  db.on("error", function (err) {
    console.error("Database connection error: ", err);
    if (err.code === "PROTOCOL_CONNECTION_LOST") {
      handleDisconnect();
    } else {
      throw err;
    }
  });
}

function handleDisconnect() {
  console.log("Reconnecting to the database...");
  createDbPool();
}

createDbPool();

async function testConnection() {
  try {
    const connection = await db.getConnection();
    console.log("Connected to the database.");
    connection.release();
  } catch (error) {
    console.error("Error connecting to the database:", error);
    handleDisconnect();
  }
}

testConnection();

// Configura la sesión
app.use(
  session({
    secret: "secret",
    resave: false,
    saveUninitialized: true,
  })
);

app.use(passport.initialize());
app.use(passport.session());

// Configura Passport con Google OAuth
passport.use(
  new GoogleStrategy(
    {
      clientID:
        "785693464680-n23a85alkt22t1e9nili98j3fpmdtq6k.apps.googleusercontent.com",
      clientSecret: "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",
      callbackURL: "http://localhost:3000/auth/google/callback",
      //callbackURL: "http://129.151.112.103.nip.io:3000/auth/google/callback",
    },
    async (token, tokenSecret, profile, done) => {
      try {
        const email = profile.emails[0].value;
        if (!email.endsWith("@mail.udp.cl")) {
          return done(null, false, { message: "No autorizado" });
        }

        console.log("Attempting to query database...");
        const [rows] = await db.query(
          "SELECT * FROM usuarios WHERE google_id = ?",
          [profile.id]
        );
        console.log("Query successful:", rows);

        if (rows.length === 0) {
          console.log("Inserting new user...");
          const [result] = await db.query(
            "INSERT INTO usuarios (google_id, nombre, email, foto) VALUES (?, ?, ?, ?)",
            [profile.id, profile.displayName, email, profile.photos[0].value]
          );
          console.log("Insert successful:", result);
          const newUser = {
            id: result.insertId,
            google_id: profile.id,
            nombre: profile.displayName,
            email: email,
            foto: profile.photos[0].value,
          };
          return done(null, newUser);
        } else {
          console.log("User found:", rows[0]);
          return done(null, rows[0]);
        }
      } catch (err) {
        console.error("Database error:", err);
        return done(err);
      }
    }
  )
);

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const [rows] = await db.query("SELECT * FROM usuarios WHERE id = ?", [id]);
    done(null, rows[0]);
  } catch (err) {
    done(err);
  }
});

// Rutas
app.get("/", (req, res) => {
  res.render("home", { user: req.user });
});

app.get("/login", (req, res) => {
  res.render("login");
});

app.get(
  "/auth/google",
  passport.authenticate("google", {
    scope: ["profile", "email"],
  })
);

app.get(
  "/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/login" }),
  (req, res) => {
    res.redirect("/user");
  }
);

app.get("/user", (req, res) => {
  if (!req.isAuthenticated()) {
    return res.redirect("/login");
  }
  res.render("user", { user: req.user });
});

app.get("/perfil", (req, res) => {
  if (!req.isAuthenticated()) {
    return res.redirect("/login");
  }
  res.send(
    `<h1>Perfil</h1><p>Nombre: ${req.user.nombre}</p><p>Email: ${req.user.email}</p><img src="${req.user.foto}" alt="Foto de perfil">`
  );
});

app.get("/logout", (req, res) => {
  req.logout((err) => {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});

// Inicia el servidor
app.listen(3000, () => {
  console.log("Servidor iniciado en http://localhost:3000");
});
