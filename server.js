const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');

const app = express();
app.use(cors());
app.use(express.json()); 

// 1. Connexion à ta base de données Supabase (Avec le bon serveur aws-1 !)
const pool = new Pool({
    connectionString: "postgresql://postgres.udtqeblrzcwtklyuzkez:ihs%40WGc.eWUC7N%2B@aws-1-eu-west-1.pooler.supabase.com:5432/postgres",
    ssl: {
        rejectUnauthorized: false // Toujours obligatoire pour le Cloud
    }
});

// 2. Route pour ENVOYER les parcelles au site web
app.get('/api/parcelles', async (req, res) => {
    try {
        const resultat = await pool.query('SELECT * FROM parcelles ORDER BY created_at DESC');
        res.json(resultat.rows);
    } catch (err) {
        console.error("Erreur lors de la lecture :", err);
        res.status(500).send("Erreur de lecture");
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
        res.json(resultat.rows[0]); 
    } catch (err) {
        console.error("Erreur lors de l'écriture :", err);
        res.status(500).send("Erreur d'enregistrement");
    }
});

// 4. Lancement du serveur (Adapté pour le Cloud)
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`✅ Serveur en ligne sur le port ${PORT}`);
});