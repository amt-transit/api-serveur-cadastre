// On charge les variables d'environnement en tout premier
require('dotenv').config();

const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const { z } = require('zod');

// ==========================================
// ROUTES AUTHENTIFICATION
// ==========================================

// 1. INSCRIPTION (Pour créer le premier compte Admin par exemple)
app.post('/api/auth/inscription', async (req, res) => {
    const { email, mot_de_passe, role } = req.body;

    try {
        // Hachage du mot de passe (on ne le sauvegarde jamais en clair !)
        const salt = await bcrypt.genSalt(10);
        const motDePasseHash = await bcrypt.hash(mot_de_passe, salt);

        const requete = `INSERT INTO utilisateurs (email, mot_de_passe_hash, role) VALUES ($1, $2, $3) RETURNING id, email, role`;
        const valeurs = [email, motDePasseHash, role || 'consultant'];
        
        const resultat = await pool.query(requete, valeurs);
        res.status(201).json({ message: "Utilisateur créé avec succès", utilisateur: resultat.rows[0] });
    } catch (err) {
        console.error(err);
        res.status(500).json({ erreur: "Erreur lors de l'inscription (Email peut-être déjà utilisé)" });
    }
});

// 2. CONNEXION
app.post('/api/auth/connexion', async (req, res) => {
    const { email, mot_de_passe } = req.body;

    try {
        // On cherche l'utilisateur
        const resultat = await pool.query(`SELECT * FROM utilisateurs WHERE email = $1`, [email]);
        if (resultat.rows.length === 0) {
            return res.status(400).json({ erreur: "Email ou mot de passe incorrect" });
        }

        const utilisateur = resultat.rows[0];

        // On vérifie le mot de passe
        const motDePasseValide = await bcrypt.compare(mot_de_passe, utilisateur.mot_de_passe_hash);
        if (!motDePasseValide) {
            return res.status(400).json({ erreur: "Email ou mot de passe incorrect" });
        }

        // On génère le jeton JWT valable 24 heures
        const token = jwt.sign(
            { id: utilisateur.id, role: utilisateur.role }, 
            process.env.JWT_SECRET, 
            { expiresIn: '24h' }
        );

        res.json({ token, role: utilisateur.role });
    } catch (err) {
        console.error(err);
        res.status(500).json({ erreur: "Erreur serveur lors de la connexion" });
    }
});
// ==========================================
// MIDDLEWARE : Le "Vigile" qui vérifie le jeton
// ==========================================
const verifierToken = (req, res, next) => {
    // On cherche le badge dans l'en-tête de la requête
    const token = req.header('Authorization')?.replace('Bearer ', '');
    
    if (!token) {
        return res.status(401).json({ erreur: "Accès refusé. Veuillez vous connecter." });
    }

    try {
        // On vérifie que le badge est authentique et non expiré
        const decode = jwt.verify(token, process.env.JWT_SECRET);
        req.utilisateur = decode; // On attache l'identité de l'utilisateur à la requête
        next(); // On le laisse passer à la suite
    } catch (err) {
        res.status(401).json({ erreur: "Jeton invalide ou expiré." });
    }
};

// Définition du schéma strict pour une Parcelle
const parcelleSchema = z.object({
  ref: z.string().min(3, "La référence doit faire au moins 3 caractères"),
  nom: z.string().min(2, "Le nom du propriétaire est obligatoire"),
  surface: z.number().positive("La surface doit être positive").nullable().optional(),
  zone: z.string().optional(),
  statut: z.enum(['Enregistrée', 'En attente', 'Litige', 'Vendue']),
  geojson: z.any().optional() // On pourrait faire une validation GeoJSON stricte plus tard
});

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

// ==========================================
// ROUTE PROTEGÉE : Création d'une parcelle
// On ajoute 'verifierToken' en 2ème argument
// ==========================================
app.post('/api/parcelles', verifierToken, async (req, res) => {
    try {
        // 1. Validation stricte (Zod)
        const donneesValidees = parcelleSchema.parse(req.body);
        
        // 2. Insérer la parcelle
        const requeteParcelle = `
            INSERT INTO parcelles (reference, proprietaire_nom, surface, zone, statut, geojson)
            VALUES ($1, $2, $3, $4, $5, $6) RETURNING *
        `;
        const valeursParcelle = [
            donneesValidees.ref, donneesValidees.nom, donneesValidees.surface, 
            donneesValidees.zone, donneesValidees.statut, JSON.stringify(donneesValidees.geojson)
        ];
        
        const resultatParcelle = await pool.query(requeteParcelle, valeursParcelle);
        const nouvelleParcelle = resultatParcelle.rows[0];

        // 3. L'AUDIT TRAIL (Historique)
        // On enregistre qui a créé la parcelle et avec quelles données
        const requeteHistorique = `
            INSERT INTO historique_modifications (parcelle_id, utilisateur_id, action, nouvelles_donnees)
            VALUES ($1, $2, $3, $4)
        `;
        // req.utilisateur.id provient de notre middleware verifierToken !
        const valeursHistorique = [nouvelleParcelle.id, req.utilisateur.id, 'CREATION', JSON.stringify(nouvelleParcelle)];
        await pool.query(requeteHistorique, valeursHistorique);

        // 4. On renvoie le résultat au front-end
        res.status(201).json(nouvelleParcelle); 
        
    } catch (err) {
        if (err instanceof z.ZodError) {
            return res.status(400).json({ erreurs: err.errors.map(e => e.message) });
        }
        console.error("Erreur lors de l'écriture :", err);
        res.status(500).json({ erreur: "Erreur serveur" });
    }
});

// 4. Lancement du serveur
// process.env.PORT sera utilisé en production, sinon le port 3000 en local
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`✅ Serveur sécurisé en ligne sur le port ${PORT}`);
});