// On charge les variables d'environnement en tout premier
require('dotenv').config();

const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');

const app = express();
app.use(cors());
app.use(express.json()); 

// Vérification de sécurité au démarrage
if (!process.env.DATABASE_URL) {
    console.error("🚨 ERREUR FATALE: DATABASE_URL manquante dans le fichier .env");
    process.exit(1); // On coupe le serveur si la BDD n'est pas configurée
}

// 1. Connexion à la base de données via la variable d'environnement
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false // Toujours obligatoire pour le Cloud Supabase
    }
});

// 2. Route pour ENVOYER les parcelles au site web
app.get('/api/parcelles', async (req, res) => {
    try {
        const resultat = await pool.query('SELECT * FROM parcelles ORDER BY created_at DESC');
        res.json(resultat.rows);
    } catch (err) {
        console.error("Erreur lors de la lecture :", err);
        res.status(500).json({ erreur: "Erreur de lecture de la base de données" });
    }
});

// 3. Route pour SAUVEGARDER une nouvelle parcelle
app.post('/api/parcelles', async (req, res) => {
    const { ref, nom, surface, zone, statut, geojson } = req.body;
    
    const requete = `
        INSERT INTO parcelles (reference, proprietaire_nom, surface, zone, statut, geojson)
        VALUES ($1, $2, $3, $4, $5, $6) RETURNING *
    `;
    const valeurs = [ref, nom, surface, zone, statut, JSON.stringify(geojson)];
    
    try {
        const resultat = await pool.query(requete, valeurs);
        res.status(201).json(resultat.rows[0]); 
    } catch (err) {
        console.error("Erreur lors de l'écriture :", err);
        res.status(500).json({ erreur: "Erreur d'enregistrement dans la base de données" });
    }
});

// 4. Lancement du serveur
// process.env.PORT sera utilisé en production, sinon le port 3000 en local
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`✅ Serveur sécurisé en ligne sur le port ${PORT}`);
});