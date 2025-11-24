// 1) Imports des bibliothèques et configuration
import { loadSequelize } from "./database.mjs"; // Charge la connexion Sequelize et les modèles (User, Task).
import express from "express"; // Framework pour créer un serveur HTTP et des routes.
import cors from "cors"; // Gère les autorisations entre origines (frontend ≠ backend).
import cookieParser from "cookie-parser"; // Lit automatiquement les cookies et les place dans req.cookies.
import jwt from "jsonwebtoken"; // Permet de créer et vérifier des JSON Web Tokens (JWT).
import bcrypt from "bcrypt"; // Sert à hacher et comparer des mots de passe.
import dotenv from "dotenv"; // Charge les variables d'environnement depuis un fichier .env.

dotenv.config(); // Charge les variables du fichier .env dans process.env.

// 2) Clé secrète pour signer/vérifier les JWT (doit exister dans .env: JWT_SECRET=...).
const JWT_SECRET = process.env.JWT_SECRET; // Si undefined, la signature/vérification du JWT échouera.

// 3) Middleware d'authentification via cookie JWT
function isLoggedInJWT(User, JWT_SECRET) {
  // Fabrique un middleware Express qui contrôle l'accès aux routes protégées.
  return async (req, res, next) => {
    try {
      // Récupère le cookie "token" (grâce à cookie-parser).
      const token = req.cookies?.token;

      // Si pas de cookie → on refuse l'accès.
      if (!token)
        return res.status(401).json({ message: "Unauthorized: No token" });

      // Vérifie la validité du JWT (signature + expiration) et récupère son contenu.
      const decoded = jwt.verify(token, JWT_SECRET);

      // Va chercher l'utilisateur en base à partir de l'id contenu dans le token.
      const user = await User.findByPk(decoded.userId);

      // Si l'utilisateur n'existe plus → on refuse.
      if (!user) return res.status(401).json({ message: "Unauthorized" });

      // Sécurité: s'assurer que le secret est bien défini.
      if (!JWT_SECRET) throw new Error("JWT_SECRET manquant");

      // Attachons des infos utiles à la requête pour la suite.
      req.userId = decoded.userId; // Id de l'utilisateur authentifié.
      req.user = user; // Objet utilisateur complet si nécessaire.

      // Tout est bon, on passe au prochain middleware/route.
      return next();
    } catch (e) {
      // Token absent, invalide ou expiré → accès refusé.
      return res.status(401).json({ message: "Unauthorized: Invalid token" });
    }
  };
}

/**
 * Point d'entrée de l'application
 * Initialise la base, crée l'app Express, déclare les middlewares et routes.
 */
async function main() {
  // 4) Connexion à la base + modèles
  const sequelize = await loadSequelize(); // Ouvre la connexion DB et charge les modèles.
  const { User, Post } = sequelize.models; // Récupère les modèles pour les utiliser dans les routes.

  // 5) Création de l'application Express
  const app = express(); // Instancie l'application serveur.

  // 6) Middlewares globaux
  app.use(cors({ credentials: true, origin: true })); // Autorise l'envoi de cookies cross-origin si besoin.
  app.use(express.json()); // Parse automatiquement le JSON du corps de la requête.
  app.use(cookieParser()); // Remplit req.cookies à partir du header "Cookie".

  // 7) Routes publiques (pas besoin d'être connecté)

  // POST /register → création d'un nouvel utilisateur
  app.post("/register", async (req, res) => {
    try {
      // On récupère les champs envoyés par le client.
      const { username, email, password, verifiedPassword } = req.body;

      // Validation des champs requis.
      if (!email || !password || !verifiedPassword || !username) {
        return res.status(400).json({
          message: "Email, password and verifiedPassword are required",
        });
      }

      // Vérifie que les deux mots de passe correspondent.
      if (password !== verifiedPassword) {
        return res.status(400).json({ message: "Passwords do not match" });
      }

      // Normalise l'email (trim + lowercase).
      const emailNorm = email.trim().toLowerCase();

      // NOTE importante: en production, il faut stocker un hash (ex: await bcrypt.hash(password, 10)).
      // Ici c'est brut pour simplifier les tests.
      const user = await User.create({
        email: emailNorm,
        username,
        password: password,
      });

      // Réponse succès (201 = créé).
      return res
        .status(201)
        .json({ message: "User registered successfully", userId: user.id });
    } catch (error) {
      // Email déjà utilisé (contrainte unique).
      if (error.name === "SequelizeUniqueConstraintError") {
        return res.status(409).json({ message: "Email already exists" });
      }
      // Erreur générique serveur.
      return res.status(500).json({ message: "Error registering user" });
    }
  });

  // POST /login → vérifie les identifiants et pose un cookie httpOnly "token"
  app.post("/login", async (req, res) => {
    try {
      // Email/mot de passe envoyés par le client.
      let { email, password } = req.body;

      // Validation des champs requis.
      if (!email || !password)
        return res.status(400).json({ message: "email et password requis" });

      // Normalise l'email pour recherche cohérente.
      email = email.trim().toLowerCase();

      // Récupère l'utilisateur par email.
      const user = await User.findOne({ where: { email } });
      console.log(user);
      if (!user) return res.status(401).json({ message: "Email invalide" });

      // Compare le mot de passe fourni avec celui stocké.
      // Version asynchrone conseillée:
      // const ok = await bcrypt.compare(password, user.password);
      // if (!ok) return res.status(401).json({ message: "Email ou mot de passe invalide" });

      // Version synchrone (OK pour tests simples).
      if (!bcrypt.compareSync(password, user.password)) {
        return res.status(401).json({ msg: "gg mec" }); // 401 si mauvais mot de passe.
      }

      // Crée un JWT contenant l'id utilisateur; expiration: 1 heure.
      const token = jwt.sign({ userId: user.id }, JWT_SECRET, {
        expiresIn: "1h",
      });

      // Dépose le cookie httpOnly "token" que le client renverra automatiquement.
      res.cookie("token", token, {
        httpOnly: true, // Non lisible via JS (protège des XSS).
        secure: process.env.NODE_ENV === "production", // En prod: cookie seulement via HTTPS.
        sameSite: process.env.NODE_ENV === "production" ? "strict" : "lax", // Strict en prod, Lax en dev.
        // maxAge: 60 * 60 * 1000, // Durée de vie: 1h (en ms).
      });

      // Envoie une réponse (nécessaire pour que Set-Cookie parte).
      return res.json({ message: "Login OK" });
    } catch (error) {
      // Erreur inattendue côté serveur.
      console.log(error);
      return res
        .status(500)
        .json({ message: "Erreur login", error: error.message });
    }
  });

  // 8) Middleware d'auth: TOUTES les routes déclarées après sont protégées
  app.use(isLoggedInJWT(User, JWT_SECRET));

  // GET /tasks → liste toutes les tâches
  app.get("/posts", async (request, response) => {
    try {
      const posts = await Post.findAll(); // Récupère toutes les tâches.
      response.json(posts); // Renvoie un tableau JSON.
    } catch (error) {
      console.log(error);
      response.status(500).json("Erreur serveur");
    }
  });

  // GET /task/:id → récupère une tâche si elle appartient à l'utilisateur authentifié
  app.get("/post/:id", async (req, res) => {
    try {
      const post = await Post.findByPk(req.params.id); // Cherche par id.
      // Vérifie l'existence et la propriété de la ressource.
      if (!post || post.UserId !== req.userId) {
        return res.status(404).json({ error: "Tâche introuvable" });
      }
      return res.json(post); // Retourne la tâche.
    } catch (error) {
      return res.status(500).json({ error: "Erreur serveur" });
    }
  });

  // POST /task → crée une nouvelle tâche associée à l'utilisateur connecté
  app.post("/post", async (req, res) => {
    try {
      const { title, content } = req.body; // Champs envoyés par le client.
      const newPost = await Post.create({
        title,
        content,
        UserId: req.userId,
      });

      return res.json(newPost); // Retourne la nouvelle tâche.
    } catch (error) {
      return res
        .status(500)
        .json({ error: "Erreur lors de la création de la tâche" });
    }
  });

  // 9) Routes utilitaires/débogage (à restreindre en production)

  // GET /user/:id → renvoie un utilisateur par id (sans contrôle fin ici).
  app.get("/user/:id", async (req, res) => {
    const user = await User.findByPk(req.params.id);
    return res.json(user);
  });

  // GET /users → renvoie tous les utilisateurs (sensible).
  app.get("/users", async (req, res) => {
    const users = await User.findAll();
    return res.json(users);
  });

  // GET /logout → supprime le cookie "token" (déconnexion)
  app.get("/logout", (req, res) => {
    res.clearCookie("token"); // Demande au client d'effacer le cookie.
    return res.json({ message: "Logout successful" });
  });

  // 10) Démarre le serveur HTTP
  app.listen(3000, () => {
    console.log("Serveur démarré sur http://localhost:3000");
  });
}

// 11) Lance l'application
main();
