const express = require("express");
const session = require("express-session");
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const mysql = require("mysql2/promise");
const path = require("path");
const multer = require("multer");


const app = express();

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.use(express.static(path.join(__dirname, "public")));
app.use('/uploads', express.static(path.join(__dirname, 'public/uploads')));


// Configura la base de datos
let db;

function createDbPool() {
  db = mysql.createPool({
    host: "localhost",
    user: "root",
    //password: "root",
    password: "1234",
    database: "notas",
    //port: 3306,
    port: 3307,
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
          "SELECT * FROM Usuario WHERE google_id = ?",
          [profile.id]
        );
        console.log("Query successful:", rows);

        if (rows.length === 0) {
          console.log("Inserting new user...");
          const [result] = await db.query(
            "INSERT INTO Usuario (google_id, nombre, email, foto) VALUES (?, ?, ?, ?)",
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
    const [rows] = await db.query("SELECT * FROM Usuario WHERE id = ?", [id]);
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

app.get("/cursos/:year", async (req, res) => {
  const year = req.params.year;

  try {
    const [rows] = await db.query("SELECT * FROM Ramo WHERE year = ?", [year]);

    const primerSemestre = rows.filter(ramo => ramo.semestre === 1);
    const segundoSemestre = rows.filter(ramo => ramo.semestre === 2);

    res.render("cursos", {
      user: req.user,
      year: year,
      primerSemestre: primerSemestre,
      segundoSemestre: segundoSemestre
    });
  } catch (error) {
    console.error("Error retrieving courses from the database:", error);
    res.status(500).send("Internal Server Error");
  }
});

app.get("/ramo/:id", async (req, res) => {
  const ramoId = req.params.id;

  try {
    const [ramoRows] = await db.query("SELECT * FROM Ramo WHERE id = ?", [ramoId]);

    if (ramoRows.length === 0) {
      return res.status(404).send("Ramo no encontrado");
    }

    const ramo = ramoRows[0];

    const [archivosRows] = await db.query("SELECT * FROM Archivo WHERE ramo = ?", [ramoId]);

    const archivos = {
      Apuntes: archivosRows.filter(archivo => archivo.categoria === "Apuntes"),
      Trabajos: archivosRows.filter(archivo => archivo.categoria === "Trabajos"),
      PDFs: archivosRows.filter(archivo => archivo.categoria === "PDFs"),
      Planos: archivosRows.filter(archivo => archivo.categoria === "Planos")
    };

    res.render("ramo", { user: req.user, ramo: ramo, archivos: archivos });
  } catch (error) {
    console.error("Error retrieving ramo from the database:", error);
    res.status(500).send("Internal Server Error");
  }
});


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

// Configurar multer para la subida de archivos
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, path.join(__dirname, 'public/uploads'));
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + path.extname(file.originalname));
  }
});

const upload = multer({
  storage: storage,
  limits: { fileSize: 1024 * 1024 * 1024 } // 1 GB
}).single('file');


app.post('/upload', (req, res) => {
  upload(req, res, async (err) => {
    if (err) {
      return res.status(400).send('Error al subir el archivo. Asegúrese de que el archivo sea menor de 1 GB.');
    }

    // Datos del archivo subido
    const { originalname, filename } = req.file;
    const directorio = filename; // Guarda solo el nombre del archivo

    // Datos adicionales del formulario
    const { categoria, profesor, ramo, year, semestre } = req.body;

    // Datos del usuario
    const id_usuario = req.user.id;

    // Guardar en la base de datos
    try {
      const [result] = await db.query(
        "INSERT INTO Archivo (id_usuario, ramo, directorio, profesor, nombre, year, semestre, categoria) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        [id_usuario, ramo, directorio, profesor, originalname, year, semestre, categoria]
      );
      console.log("Archivo guardado en la base de datos:", result);

      res.send('Archivo subido y guardado con éxito.');
    } catch (dbError) {
      console.error("Error al guardar el archivo en la base de datos:", dbError);
      res.status(500).send("Error interno del servidor al guardar el archivo.");
    }
  });
});


// Inicia el servidor
app.listen(3000, () => {
  console.log("Servidor iniciado en http://localhost:3000");
});
