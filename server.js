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
// MIDDLEWARE : Le "Vigile" des Administrateurs
// ==========================================
const verifierRoleAdmin = (req, res, next) => {
    // req.utilisateur vient du middleware 'verifierToken' qui a tourné juste avant
    if (req.utilisateur.role !== 'admin') {
        return res.status(403).json({ 
            erreur: "Accès refusé. Cette action nécessite des privilèges d'administrateur." 
        });
    }
    next(); // C'est un admin, on le laisse passer !
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
    geojson: z.any().optional(),
    // On ajoute tous les nouveaux champs ici :
    type: z.string().optional(),
    ilot: z.string().optional(),
    obs: z.string().optional(),
    tel: z.string().optional(),
    cni: z.string().optional(),
    adresse: z.string().optional(),
    acquisition: z.string().optional()
});


// ==========================================
// ROUTES AUTHENTIFICATION
// ==========================================
app.post('/api/auth/inscription', async (req, res) => {
    const { nom, email, mot_de_passe, role } = req.body;

    if (!nom || !email || !mot_de_passe) {
        return res.status(400).json({ erreur: "Le nom, l'email et le mot de passe sont obligatoires." });
    }

    try {
        const salt = await bcrypt.genSalt(10);
        const motDePasseHash = await bcrypt.hash(mot_de_passe, salt);

        const requete = `INSERT INTO utilisateurs (nom, email, mot_de_passe_hash, role) VALUES ($1, $2, $3, $4) RETURNING id, nom, email, role`;
        const valeurs = [nom, email, motDePasseHash, role || 'consultant'];
        
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

        res.json({ token, role: utilisateur.role, nom: utilisateur.nom });
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
            INSERT INTO parcelles (
                reference, proprietaire_nom, surface, zone, statut, geojson,
                type_usage, ilot_lot, observations, proprietaire_tel, 
                proprietaire_cni, proprietaire_adresse, proprietaire_acquisition
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) RETURNING *
        `;
        const valeursParcelle = [
            donneesValidees.ref, donneesValidees.nom, donneesValidees.surface, 
            donneesValidees.zone, donneesValidees.statut, JSON.stringify(donneesValidees.geojson),
            donneesValidees.type, donneesValidees.ilot, donneesValidees.obs,
            donneesValidees.tel, donneesValidees.cni, donneesValidees.adresse, donneesValidees.acquisition
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
// 📖 ROUTE : Récupérer l'historique d'une parcelle
// ==========================================
app.get('/api/parcelles/:id/historique', verifierToken, async (req, res) => {
    try {
        const { id } = req.params;
        // On joint la table 'utilisateurs' pour récupérer le nom (ou l'email à défaut) de la personne
        const query = `
            SELECT h.action, h.cree_le, COALESCE(u.nom, u.email) as auteur, h.donnees_precedentes, h.nouvelles_donnees
            FROM historique_modifications h
            LEFT JOIN utilisateurs u ON h.utilisateur_id = u.id
            WHERE h.parcelle_id = $1
            ORDER BY h.cree_le DESC
        `;
        const resultat = await pool.query(query, [id]);
        res.json(resultat.rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ erreur: "Erreur lors de la récupération de l'historique" });
    }
});

// ==========================================
// 📖 ROUTE PROTEGÉE : Historique Global (Audit Trail pour Admin)
// ==========================================
app.get('/api/admin/audit', verifierToken, verifierRoleAdmin, async (req, res) => {
    try {
        const query = `
            SELECT 
                h.action, 
                COALESCE(u.nom, u.email) as auteur, 
                p.reference as reference_parcelle,
                h.cree_le,
                h.donnees_precedentes,
                h.nouvelles_donnees
            FROM historique_modifications h
            LEFT JOIN utilisateurs u ON h.utilisateur_id = u.id
            LEFT JOIN parcelles p ON h.parcelle_id = p.id
            ORDER BY h.cree_le DESC
        `;
        const resultat = await pool.query(query);
        res.json(resultat.rows);
    } catch (err) {
        console.error("Erreur lors de la récupération de l'audit :", err);
        res.status(500).json({ erreur: "Erreur lors de la récupération de l'audit global" });
    }
});

// ==========================================
// 👤 ROUTE PROTEGÉE : Créer un utilisateur (Admin uniquement)
// ==========================================
app.post('/api/admin/utilisateurs', verifierToken, verifierRoleAdmin, async (req, res) => {
    const { nom, email, mot_de_passe, role } = req.body;

    if (!nom || !email || !mot_de_passe || !role) {
        return res.status(400).json({ erreur: "Tous les champs (nom, email, mot_de_passe, role) sont obligatoires." });
    }

    try {
        const salt = await bcrypt.genSalt(10);
        const motDePasseHash = await bcrypt.hash(mot_de_passe, salt);

        const requete = `INSERT INTO utilisateurs (nom, email, mot_de_passe_hash, role) VALUES ($1, $2, $3, $4) RETURNING id, nom, email, role`;
        const valeurs = [nom, email, motDePasseHash, role];
        
        const resultat = await pool.query(requete, valeurs);
        res.status(201).json({ message: "Utilisateur créé avec succès", utilisateur: resultat.rows[0] });
    } catch (err) {
        console.error("Erreur lors de la création d'utilisateur :", err);
        res.status(500).json({ erreur: "Erreur lors de la création de l'utilisateur (L'email est peut-être déjà utilisé)." });
    }
});

// ==========================================
// ✏️ ROUTE PROTEGÉE : Modifier une parcelle (PUT)
// ==========================================
app.put('/api/parcelles/:id', verifierToken, verifierRoleAdmin, async (req, res) => {
    const { id } = req.params;
    try {
        const donneesValidees = parcelleSchema.parse(req.body);

        // 1. Récupérer l'ancienne version pour l'historique
        const oldRes = await pool.query('SELECT * FROM parcelles WHERE id = $1', [id]);
        if(oldRes.rows.length === 0) return res.status(404).json({erreur: "Parcelle introuvable"});
        const ancienneParcelle = oldRes.rows[0];

        // 2. Mettre à jour la parcelle
        const requeteUpdate = `
            UPDATE parcelles
            SET reference = $1, proprietaire_nom = $2, surface = $3, zone = $4, statut = $5, geojson = $6,
                type_usage = $7, ilot_lot = $8, observations = $9, proprietaire_tel = $10,
                proprietaire_cni = $11, proprietaire_adresse = $12, proprietaire_acquisition = $13
            WHERE id = $14 RETURNING *
        `;
        const valeursUpdate = [
            donneesValidees.ref, donneesValidees.nom, donneesValidees.surface,
            donneesValidees.zone, donneesValidees.statut, JSON.stringify(donneesValidees.geojson),
            donneesValidees.type, donneesValidees.ilot, donneesValidees.obs,
            donneesValidees.tel, donneesValidees.cni, donneesValidees.adresse, donneesValidees.acquisition,
            id
        ];
        const resultUpdate = await pool.query(requeteUpdate, valeursUpdate);
        const parcelleAjour = resultUpdate.rows[0];

        // 3. 🛡️ L'AUDIT TRAIL : Enregistrer la modification
        await pool.query(`
            INSERT INTO historique_modifications (parcelle_id, utilisateur_id, action, donnees_precedentes, nouvelles_donnees)
            VALUES ($1, $2, $3, $4, $5)
        `, [id, req.utilisateur.id, 'MODIFICATION', JSON.stringify(ancienneParcelle), JSON.stringify(parcelleAjour)]);

        res.json(parcelleAjour);
    } catch (err) {
        if (err instanceof z.ZodError) return res.status(400).json({ erreurs: err.errors.map(e => e.message) });
        console.error(err); res.status(500).json({ erreur: "Erreur serveur" });
    }
});

// ==========================================
// 🗑️ ROUTE PROTEGÉE : Supprimer une parcelle (DELETE)
// ==========================================
app.delete('/api/parcelles/:id', verifierToken, verifierRoleAdmin, async (req, res) => {
    const { id } = req.params;
    try {
        // 1. Récupérer les données avant de les détruire
        const oldRes = await pool.query('SELECT * FROM parcelles WHERE id = $1', [id]);
        if(oldRes.rows.length === 0) return res.status(404).json({erreur: "Parcelle introuvable"});
        const ancienneParcelle = oldRes.rows[0];

        // 2. Supprimer la parcelle
        await pool.query('DELETE FROM parcelles WHERE id = $1', [id]);

        // 3. 🛡️ L'AUDIT TRAIL : Enregistrer la suppression
        await pool.query(`
            INSERT INTO historique_modifications (utilisateur_id, action, donnees_precedentes)
            VALUES ($1, $2, $3)
        `, [req.utilisateur.id, 'SUPPRESSION', JSON.stringify(ancienneParcelle)]);

        res.json({ message: "Parcelle supprimée" });
    } catch (err) {
        console.error(err); res.status(500).json({ erreur: "Erreur serveur" });
    }
});

// ==========================================
// LANCEMENT DU SERVEUR
// ==========================================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`✅ Serveur sécurisé en ligne sur le port ${PORT}`);
});