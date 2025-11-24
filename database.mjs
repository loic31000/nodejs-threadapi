// On importe le module Sequelize et les types de données nécessaires
import Sequelize, { DataTypes } from 'sequelize'

// On importe la librairie bcrypt pour chiffrer les mots de passe
import bcrypt from 'bcrypt'

// On définit une fonction asynchrone pour charger et configurer Sequelize
export async function loadSequelize() {
  try {
    // Les informations de connexion à la base de données (nom, utilisateur, mot de passe)
    const login = { database: 'threadapi-database', username: 'root', password: 'root' } 

    // On crée une instance de Sequelize configurée pour utiliser MySQL en local
    const sequelize = new Sequelize(login.database, login.username, login.password, {
      host: '127.0.0.1',
      dialect: 'mysql',
    })

    // On définit le modèle "User" (utilisateur) avec ses champs
    const User = sequelize.define('User', {
      // Le nom d'utilisateur, de type chaîne de caractères
      username: DataTypes.STRING,
      // L'adresse email, unique et de type chaîne de caractères
      email: { type: DataTypes.STRING, unique: true },
      // Le mot de passe, qui sera automatiquement chiffré en base
      password: {
        type: DataTypes.STRING,
        set(clear) { // Cette méthode s'exécute automatiquement quand on donne un mot de passe
          const hashed = bcrypt.hashSync(clear, 10) // On chiffre le mot de passe en utilisant bcrypt
          this.setDataValue('password', hashed) // On stocke la version chiffrée en base
        },
      },
    })

    // On définit le modèle "Post" (tâche) avec ses champs
    const Post = sequelize.define('Post', {
      // Le titre du post
      title: DataTypes.TEXT,
      // Le contenu ou la description du post
      content: DataTypes.TEXT,
    })
    
    const Commentaire = sequelize.define('Commentaire', {
        title: DataTypes.TEXT,
        content: DataTypes.TEXT,
    })


    // On crée la relation : un utilisateur possède plusieurs postes
    User.hasMany(Post)
    User.hasMany(Commentaire)
    Post.hasMany(Commentaire)
    // On crée la relation inverse : un post appartient à un utilisateur
    Post.belongsTo(User)
    Commentaire.belongsTo(User)
    Commentaire.belongsTo(Post)

    // On teste la connexion à la base de données
    await sequelize.authenticate()
    // On synchronise les modèles avec la base (force:true efface tout et recrée les tables à chaque fois)
    await sequelize.sync({ force: true })

    // On crée un utilisateur "Billy" avec un mot de passe chiffré automatiquement
    const billy = await User.create({ username: 'Billy', email: 'billy@mail.com', password: 'billy123' })
    // "Billy" crée une tâche : faire les courses, avec une petite liste
    await billy.createPost({ title: 'Faire les courses', content: 'ananas, savon, éponge' })

    // On retourne l'objet sequelize pour éventuellement l’utiliser ailleurs
    return sequelize
  } catch (error) {
    // En cas d’erreur de connexion, on affiche l’erreur dans la console
    console.log(error)
    // On lève une nouvelle erreur personnalisée pour signaler le problème
    throw new Error('Impossible de se connecter à la base de données')
  }
}
