// 1) Imports des bibliothèques et configuration
import { loadSequelize } from "./database.mjs"; // Charge la connexion Sequelize et les modèles (User, Post, Commentaire).
import express from "express"; // Framework pour créer un serveur HTTP et gérer les routes.
import cors from "cors"; // Permet de gérer les autorisations CORS entre frontend et backend.
import cookieParser from "cookie-parser"; // Parse automatiquement les cookies dans les requêtes.
import jwt from "jsonwebtoken"; // Permet de créer et vérifier des JSON Web Tokens (JWT) pour l'authentification.
import bcrypt from "bcrypt"; // Permet de hacher et comparer les mots de passe.
import dotenv from "dotenv"; // Charge les variables d'environnement depuis un fichier .env.

// Charge les variables d'environnement dans process.env
dotenv.config();

// 2) Récupération de la clé secrète pour signer/vérifier les JWT
const JWT_SECRET = process.env.JWT_SECRET; // Doit être défini dans le fichier .env sinon la validation échouera.

// 3) Middleware d'authentification via cookie JWT
function isLoggedInJWT(User, JWT_SECRET) {
  // Crée un middleware express qui vérifie la validité du JWT dans le cookie "token"
  return async (req, res, next) => {
    try {
      // Récupère le token JWT dans les cookies de la requête
      const token = req.cookies?.token;

      // Si aucun token, accès refusé : utilisateur non authentifié
      if (!token)
        return res.status(401).json({ message: "Accès refusé : aucun token trouvé" });

      // Vérifie que le token est valide et non expiré
      const decoded = jwt.verify(token, JWT_SECRET);

      // Cherche l'utilisateur en base grâce à l'ID contenu dans le token
      const user = await User.findByPk(decoded.userId);

      // Si utilisateur introuvable → accès refusé (token invalide)
      if (!user) return res.status(401).json({ message: "Accès refusé : utilisateur non trouvé" });

      // Vérifie que la clé JWT_SECRET est bien définie
      if (!JWT_SECRET) throw new Error("Clé secrète JWT absente");

      // Stocke des infos utiles dans l'objet req pour la suite (id et objet utilisateur complet)
      req.userId = decoded.userId;
      req.user = user;

      // Passe au middleware ou route suivante
      return next();
    } catch (e) {
      // En cas de token invalide ou expiré, accès refusé
      return res.status(401).json({ message: "Accès refusé : token invalide ou expiré" });
    }
  };
}

/**
 * Point d'entrée de l'application
 * Initialise la connexion DB, crée l'app Express, déclare middlewares et routes.
 */
async function main() {
  // 4) Connexion à la base + récupération des modèles
  const sequelize = await loadSequelize(); // Charge la connexion et les modèles Sequelize
  const { User, Post, Commentaire } = sequelize.models; // Récupère les modèles pour les utiliser dans les routes

  // 5) Création de l'application Express
  const app = express();

  // 6) Déclaration des middlewares globaux
  app.use(cors({ credentials: true, origin: true })); // Autorise le partage de ressources cross-origin avec cookies
  app.use(express.json()); // Analyse automatiquement le corps des requêtes JSON
  app.use(cookieParser()); // Permet de récupérer les cookies via req.cookies

  // 7) Routes publiques (pas besoin d'être connecté)

  // Route POST /register : création d'un utilisateur
  app.post("/register", async (req, res) => {
    try {
      // Récupération des champs depuis le corps de requête
      const { username, email, password, verifiedPassword } = req.body;

      // Validation : vérifier que tous les champs obligatoires sont présents
      if (!email || !password || !verifiedPassword || !username) {
        return res.status(400).json({
          message: "Les champs email, username, password et verifiedPassword sont requis",
        });
      }

      // Validation : vérifier que les deux mots de passe correspondent
      if (password !== verifiedPassword) {
        return res.status(400).json({ message: "Les mots de passe ne correspondent pas" });
      }

      // Normalisation de l'email : suppression des espaces et passage en minuscules
      const emailNorm = email.trim().toLowerCase();

      // Création de l'utilisateur en base de données
      // Note : le mot de passe est automatiquement hashé par le modèle User
      const user = await User.create({
        email: emailNorm,
        username,
        password: password,
      });

      // Réponse succès : utilisateur créé avec code 201
      return res
        .status(201)
        .json({ message: "Utilisateur créé avec succès", userId: user.id });
    } catch (error) {
      // Gestion des erreurs : email en doublon
      if (error.name === "SequelizeUniqueConstraintError") {
        return res.status(409).json({ message: "Cet email est déjà utilisé" });
      }
      // Erreur serveur générique
      return res.status(500).json({ message: "Erreur lors de la création de l'utilisateur" });
    }
  });

  // Route POST /login : authentification et génération du cookie JWT
  app.post("/login", async (req, res) => {
    try {
      // Récupération des identifiants envoyés
      let { email, password } = req.body;

      // Validation des champs
      if (!email || !password)
        return res.status(400).json({ message: "Email et mot de passe requis" });

      // Normalisation de l'email
      email = email.trim().toLowerCase();

      // Recherche de l'utilisateur par email
      const user = await User.findOne({ where: { email } });

      // Si utilisateur non trouvé, répond avec erreur 401
      if (!user) return res.status(401).json({ message: "Email incorrect" });

      // Comparaison du mot de passe fourni avec celui stocké en base
      if (!bcrypt.compareSync(password, user.password)) {
        return res.status(401).json({ message: "Mot de passe incorrect" });
      }

      // Génération d'un token JWT valide 1 heure
      const token = jwt.sign({ userId: user.id }, JWT_SECRET, {
        expiresIn: "1h",
      });

      // Envoi du cookie httpOnly avec le token
      res.cookie("token", token, {
        httpOnly: true, // Le cookie n'est pas accessible via JS côté client (protège du XSS)
        secure: process.env.NODE_ENV === "production", // En prod, cookie HTTPS uniquement
        sameSite: process.env.NODE_ENV === "production" ? "strict" : "lax", // Politique de même site pour le cookie
      });

      // Réponse succès
      return res.json({ message: "Connexion réussie" });
    } catch (error) {
      // En cas d'erreur inattendue serveur, affichage dans la console et réponse 500
      console.log(error);
      return res.status(500).json({ message: "Erreur lors de la connexion", error: error.message });
    }
  });

  // 8) Middleware d'authentification : toutes les routes suivantes sont protégées
  app.use(isLoggedInJWT(User, JWT_SECRET));

  // Route GET /posts : récupération de tous les posts
  app.get("/posts", async (request, response) => {
    try {
      // Cherche tous les posts en base
      const posts = await Post.findAll();
      // Renvoie un tableau JSON des posts
      response.json(posts);
    } catch (error) {
      console.log(error);
      response.status(500).json({ message: "Erreur serveur lors de la récupération des posts" });
    }
  });

  // Route GET /post/:id : récupère un post par id si l'utilisateur est l'auteur
  app.get("/post/:id", async (req, res) => {
    try {
      // Recherche du post par clé primaire (id)
      const post = await Post.findByPk(req.params.id);
      // Vérifie si le post existe et si l'utilisateur est le propriétaire (auteur)
      if (!post || post.UserId !== req.userId) {
        return res.status(404).json({ error: "Post non trouvé ou accès interdit" });
      }
      // Renvoie le post
      return res.json(post);
    } catch (error) {
      return res.status(500).json({ error: "Erreur serveur lors de la récupération du post" });
    }
  });

  // Route POST /post : création d'un post pour l'utilisateur connecté
  app.post("/post", async (req, res) => {
    try {
      // Récupération des champs envoyés dans la requête
      const { title, content } = req.body;
      // Création d'un nouveau post lié à l'utilisateur connecté (id dans req.userId)
      const newPost = await Post.create({
        title,
        content,
        UserId: req.userId,
      });
      // Renvoie le post créé
      return res.json(newPost);
    } catch (error) {
      return res.status(500).json({ error: "Erreur serveur lors de la création du post" });
    }
  });

  // Route POST /posts/:postId/commentaire : ajout d'un commentaire à un post
  app.post("/posts/:postId/commentaire", async (req, res) => {
    try {
      // Récupère les champs dans le corps de la requête
      const { title, content, postId } = req.body;
      const userId = req.userId; // Id utilisateur authentifié

      // Validation : postId obligatoire pour savoir à quel post rattacher le commentaire
      if (!postId) {
        return res.status(400).json({ error: "Le champ postId est obligatoire" });
      }

      // Création du commentaire avec les liens vers utilisateur et post
      const newCommentaire = await Commentaire.create({
        title,
        content,
        UserId: userId,
        PostId: postId,
      });

      // Renvoie le commentaire créé
      return res.json(newCommentaire);
    } catch (error) {
      console.log(error);
      // Erreur serveur en cas d’échec
      return res.status(500).json({ error: "Erreur serveur lors de la création du commentaire" });
    }
  });

  // 9) Routes de débogage/utilitaires (à protéger en production)

  // Route GET /user/:id : récupère un utilisateur sans authentification avancée
  app.get("/user/:id", async (req, res) => {
    const user = await User.findByPk(req.params.id);
    return res.json(user);
  });

  // Route GET /users : récupère tous les utilisateurs (en principe à restreindre)
  app.get("/users", async (req, res) => {
    const users = await User.findAll();
    return res.json(users);
  });

  // Route DELETE /posts/:postId : supprime un post si l'utilisateur est auteur ou admin
  app.delete("/posts/:postId", async (req, res) => {
    try {
      const { postId } = req.params; // Récupère l'id dans l'URL
      const userId = req.userId; // Id de l'utilisateur connecté

      // Recherche du post par id
      const post = await Post.findByPk(postId);
      if (!post) return res.status(404).json({ error: "Post non trouvé" });

      // Vérifie que l'utilisateur est bien l'auteur ou a le rôle admin
      if (post.UserId !== userId && !req.user.isAdmin) {
        return res.status(403).json({ error: "Accès refusé : non auteur ni admin" });
      }

      // Supprime le post
      await post.destroy();

      return res.json({ message: "Post supprimé avec succès" });
    } catch (error) {
      console.error(error);
      return res.status(500).json({ error: "Erreur serveur lors de la suppression du post" });
    }
  });

  // Route DELETE /comments/:commentId : supprime un commentaire si l'utilisateur est auteur ou admin
  app.delete("/comments/:commentId", async (req, res) => {
    try {
      const { commentId } = req.params; // Récupère l'id dans l’URL
      const userId = req.userId; // Id de l'utilisateur connecté

      // Recherche du commentaire par id
      const commentaire = await Commentaire.findByPk(commentId);
      if (!commentaire) return res.status(404).json({ error: "Commentaire non trouvé" });

      // Vérifie que l'utilisateur est auteur ou admin
      if (commentaire.UserId !== userId && !req.user.isAdmin) {
        return res.status(403).json({ error: "Accès refusé : non auteur ni admin" });
      }

      // Supprime le commentaire
      await commentaire.destroy();

      return res.json({ message: "Commentaire supprimé avec succès" });
    } catch (error) {
      console.error(error);
      return res.status(500).json({ error: "Erreur serveur lors de la suppression du commentaire" });
    }
  });

  // Route GET /logout : supprime le cookie "token" pour déconnecter l'utilisateur
  app.get("/logout", (req, res) => {
    res.clearCookie("token"); // Demande au navigateur de retirer le cookie
    return res.json({ message: "Déconnexion réussie" });
  });

  // 10) Démarre le serveur HTTP sur le port 3000
  app.listen(3000, () => {
    console.log("Serveur démarré sur http://localhost:3000");
  });
}

// 11) Lance l'application principale
main();

