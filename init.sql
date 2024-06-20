CREATE DATABASE IF NOT EXISTS notas;
USE notas;

CREATE TABLE IF NOT EXISTS Usuario (
  id INT AUTO_INCREMENT PRIMARY KEY,
  google_id VARCHAR(255) NOT NULL,
  nombre VARCHAR(255) NOT NULL,
  email VARCHAR(255) NOT NULL,
  foto VARCHAR(255),
  tipo_usuario BINARY(1) DEFAULT 0,
  UNIQUE (google_id)
);

-- Tabla Ramo
CREATE TABLE IF NOT EXISTS Ramo (
  id INT AUTO_INCREMENT PRIMARY KEY,
  nombre TEXT NOT NULL,
  year INT NOT NULL,
  semestre INT NOT NULL,
  descripcion TEXT,
  color TEXT
);

-- Tabla Archivo
CREATE TABLE IF NOT EXISTS Archivo (
  id INT AUTO_INCREMENT PRIMARY KEY,
  id_usuario INT NOT NULL,
  ramo INT NOT NULL,
  directorio TEXT NOT NULL,
  profesor TEXT,
  nombre TEXT NOT NULL,
  year INT NOT NULL,
  semestre INT NOT NULL,
  categoria TEXT,
  FOREIGN KEY (id_usuario) REFERENCES Usuario(id),
  FOREIGN KEY (ramo) REFERENCES Ramo(id)
);

-- Tabla Favorito
CREATE TABLE IF NOT EXISTS Favorito (
  id INT AUTO_INCREMENT PRIMARY KEY,
  id_usuario INT NOT NULL,
  id_archivo INT NOT NULL,
  FOREIGN KEY (id_usuario) REFERENCES Usuario(id),
  FOREIGN KEY (id_archivo) REFERENCES Archivo(id)
);

-- Tabla Comentarios
CREATE TABLE IF NOT EXISTS Comentarios (
  id INT AUTO_INCREMENT PRIMARY KEY,
  id_usuario INT NOT NULL,
  comentario TEXT,
  id_archivo INT NOT NULL,
  fecha DATE,
  FOREIGN KEY (id_usuario) REFERENCES Usuario(id),
  FOREIGN KEY (id_archivo) REFERENCES Archivo(id)
);