// database.mjs

// Import des modules nécessaires depuis Sequelize
import Sequelize, { DataTypes } from 'sequelize'

// Import de bcrypt pour le hachage des mots de passe
import bcrypt from 'bcrypt'

// Fonction asynchrone qui configure la connexion à la base et définit les modèles
export async function loadSequelize() {
  try {
    // Informations de connexion à la base de données MySQL locale
    const login = { database: 'threadapi-database', username: 'root', password: 'root' };

    // Création de l'instance Sequelize configurée
    const sequelize = new Sequelize(login.database, login.username, login.password, {
      host: '127.0.0.1',
      dialect: 'mysql',
    });

    // Définition du modèle User (utilisateur)
    const User = sequelize.define('User', {
      // Nom d'utilisateur
      username: DataTypes.STRING,
      // Email, qui doit être unique
      email: { type: DataTypes.STRING, unique: true },
      // Mot de passe, stocké hashé automatiquement grâce à cette méthode set
      password: {
        type: DataTypes.STRING,
        set(clear) {
          // Hash du mot de passe avec bcrypt, 10 tours
          const hashed = bcrypt.hashSync(clear, 10);
          // Stockage du hash au lieu du texte clair en base
          this.setDataValue('password', hashed);
        },
      },
    });

    // Définition du modèle Post (article ou tâche)
    const Post = sequelize.define('Post', {
      title: DataTypes.TEXT, // Titre du post
      content: DataTypes.TEXT, // Contenu du post
    });

    // Définition du modèle Commentaire
    const Commentaire = sequelize.define('Commentaire', {
      title: DataTypes.TEXT, // Titre du commentaire
      content: DataTypes.TEXT, // Contenu du commentaire
    });

    // Définition des relations entre les modèles :
    User.hasMany(Post); // Un utilisateur a plusieurs posts
    User.hasMany(Commentaire); // Un utilisateur a plusieurs commentaires
    Post.hasMany(Commentaire); // Un post a plusieurs commentaires
    Post.belongsTo(User); // Un post appartient à un utilisateur
    Commentaire.belongsTo(User); // Un commentaire appartient à un utilisateur
    Commentaire.belongsTo(Post); // Un commentaire appartient à un post

    // Test de connexion à la base
    await sequelize.authenticate();

    // Synchronisation : recrée les tables à chaque lancement (force:true)
    await sequelize.sync({ force: true });

    // Insertion de test : création d'un utilisateur
    const billy = await User.create({ username: 'Billy', email: 'billy@mail.com', password: 'billy123' });

    // Insertion d'un post lié à Billy
    await billy.createPost({ title: 'Faire les courses', content: 'ananas, savon, éponge' });

    // Retourne l'objet sequelize pour l'utiliser dans d'autres fichiers
    return sequelize;

  } catch (error) {
    // Affiche l'erreur en console si problème de connexion ou autre
    console.log(error);
    // Renvoie une erreur personnalisée
    throw new Error('Impossible de se connecter à la base de données');
  }
}

