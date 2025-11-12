# Installer les dépendances
```bash
npm install
```

# Lancer l'application
```bash
npm run dev
```

# Lancer le container docker de mysql

```bash
docker run -p 3306:3306 -e MYSQL_ROOT_PASSWORD=root -d --name=bdd mysql
```