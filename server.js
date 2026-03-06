// On charge les variables d'environnement en tout premier
require('dotenv').config();

const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { z } = require('zod');

const app = express();
app.use(cors());
app.use(express.json());

// Vérification de sécurité au démarrage
if (!process.env.DATABASE_URL) {
    console.error("🚨 ERREUR FATALE: DATABASE_URL manquante");
    process.exit(1);
}

// ==========================================
// CONFIGURATION DE LA BASE DE DONNÉES
// ==========================================
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

// ==========================================
// MIDDLEWARE : Le "Vigile" qui vérifie le jeton
// ==========================================
const verifierToken = (req, res, next) => {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    
    if (!token) {
        return res.status(401).json({ erreur: "Accès refusé. Veuillez vous connecter." });
    }

    try {
        const decode = jwt.verify(token, process.env.JWT_SECRET);
        req.utilisateur = decode;
        next();
    } catch (err) {
        res.status(401).json({ erreur: "Jeton invalide ou expiré." });
    }
};

// ==========================================
// SCHÉMAS DE VALIDATION (Le Bouclier)
// ==========================================
const parcelleSchema = z.object({
    ref: z.string().min(3, "La référence doit faire au moins 3 caractères"),
    nom: z.string().min(2, "Le nom du propriétaire est obligatoire"),
    surface: z.number().positive("La surface doit être positive").nullable().optional(),
    zone: z.string().optional(),
    statut: z.enum(['Enregistrée', 'En attente', 'Litige', 'Vendue']),
    geojson: z.any().optional()
});

// ==========================================
// ROUTES AUTHENTIFICATION
// ==========================================
app.post('/api/auth/inscription', async (req, res) => {
    const { email, mot_de_passe, role } = req.body;
    try {
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

app.post('/api/auth/connexion', async (req, res) => {
    const { email, mot_de_passe } = req.body;
    try {
        const resultat = await pool.query(`SELECT * FROM utilisateurs WHERE email = $1`, [email]);
        if (resultat.rows.length === 0) {
            return res.status(400).json({ erreur: "Email ou mot de passe incorrect" });
        }

        const utilisateur = resultat.rows[0];
        const motDePasseValide = await bcrypt.compare(mot_de_passe, utilisateur.mot_de_passe_hash);
        
        if (!motDePasseValide) {
            return res.status(400).json({ erreur: "Email ou mot de passe incorrect" });
        }

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
// ROUTES API PARCELLES
// ==========================================
app.get('/api/parcelles', async (req, res) => {
    try {
        const resultat = await pool.query('SELECT * FROM parcelles ORDER BY created_at DESC');
        res.json(resultat.rows);
    } catch (err) {
        console.error("Erreur lors de la lecture :", err);
        res.status(500).json({ erreur: "Erreur de lecture de la BDD" });
    }
});

app.post('/api/parcelles', verifierToken, async (req, res) => {
    try {
        const donneesValidees = parcelleSchema.parse(req.body);
        
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

        const requeteHistorique = `
            INSERT INTO historique_modifications (parcelle_id, utilisateur_id, action, nouvelles_donnees)
            VALUES ($1, $2, $3, $4)
        `;
        const valeursHistorique = [nouvelleParcelle.id, req.utilisateur.id, 'CREATION', JSON.stringify(nouvelleParcelle)];
        await pool.query(requeteHistorique, valeursHistorique);

        res.status(201).json(nouvelleParcelle); 
        
    } catch (err) {
        if (err instanceof z.ZodError) {
            return res.status(400).json({ erreurs: err.errors.map(e => e.message) });
        }
        console.error("Erreur lors de l'écriture :", err);
        res.status(500).json({ erreur: "Erreur serveur" });
    }
});

// ==========================================
// LANCEMENT DU SERVEUR
// ==========================================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`✅ Serveur sécurisé en ligne sur le port ${PORT}`);
});