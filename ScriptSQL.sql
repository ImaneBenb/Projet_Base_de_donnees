-- ==============================
-- Création des tables principales
-- ==============================

CREATE TABLE Menaces(
    id_menace INT PRIMARY KEY AUTO_INCREMENT,               -- Identifiant unique de la menace
    nom_menace VARCHAR(50) NOT NULL UNIQUE,                 -- Nom unique de la menace
    description VARCHAR(450) NOT NULL                       -- Description obligatoire
);

CREATE TABLE Actifs (
    id_actif INT PRIMARY KEY AUTO_INCREMENT,                -- Identifiant unique de l'actif
    localisation VARCHAR(100) NOT NULL,                     -- Localisation obligatoire
    type_actif VARCHAR(50) NOT NULL ,                       -- Type obligatoire avec valeurs autorisées
    criticité VARCHAR(50) NOT NULL CHECK (criticité IN ('Faible','Moyen','Elevé','Critique'))
    -- Criticité obligatoire et restreinte à ces valeurs
);

CREATE TABLE Vulnerabilites (
    id_vulnerabilite INT PRIMARY KEY AUTO_INCREMENT,        -- Identifiant unique
    CVE VARCHAR(50) NOT NULL,                               -- CVE obligatoire
    CVSS_Score DECIMAL(3,1) NOT NULL CHECK (CVSS_Score >= 0 AND CVSS_Score <= 10)
    -- Score CVSS obligatoire entre 0 et 10
);

CREATE TABLE Sources_d_alerte (
    id_source INT PRIMARY KEY AUTO_INCREMENT,               -- Identifiant unique
    type_source VARCHAR(50) NOT NULL,                       -- Type de source obligatoire (SIEM, IDS…)
    outil VARCHAR(100) NOT NULL,                            -- Nom de l'outil ayant généré l'alerte
    description VARCHAR(450) NOT NULL                       -- Message ou résumé de l'alerte
);

CREATE TABLE Equipes (
    id_equipe INT PRIMARY KEY AUTO_INCREMENT,              -- Identifiant unique
    nom_equipe VARCHAR(50) NOT NULL UNIQUE,                -- Nom de l'équipe unique
    domaine_d_expertise VARCHAR(50) NOT NULL,              -- Spécialité (SOC, Réseau, Forensic…)
    contact VARCHAR(100) NOT NULL UNIQUE                   -- Contact mail unique
);

CREATE TABLE Incident (
    id_Incident INT PRIMARY KEY AUTO_INCREMENT,            -- Identifiant unique
    type_incident VARCHAR(50) NOT NULL,                    -- Type obligatoire (intrusion, malware…)
    niveau_gravite VARCHAR(50) NOT NULL CHECK (niveau_gravite IN ('Faible', 'Moyen', 'Elevé', 'Critique')),
    date_detection DATE NOT NULL,                          -- Date de détection obligatoire
    date_resolution DATE,                                  -- Date de résolution non obligatoire    
    statut VARCHAR(50) NOT NULL CHECK (statut IN ('En cours','Résolu')), -- Statut obligatoire
    description VARCHAR(450) NOT NULL                      -- Description obligatoire
);

CREATE TABLE Membre (
    id_membre INT PRIMARY KEY AUTO_INCREMENT,              -- Identifiant unique
    nom VARCHAR(50) NOT NULL,                              -- Nom obligatoire
    prenom VARCHAR(50) NOT NULL,                           -- Prénom obligatoire
    mail VARCHAR(100) NOT NULL UNIQUE,                     -- Mail unique obligatoire
    telephone VARCHAR(20) NOT NULL,                        -- Téléphone obligatoire
    id_equipe INT NOT NULL,                                -- Chaque membre appartient à une seule équipe (1..1)
    FOREIGN KEY (id_equipe) REFERENCES Equipes(id_equipe)
        ON DELETE CASCADE
        ON UPDATE CASCADE
);

CREATE TABLE Actions_Correctives (
    id_action INT PRIMARY KEY AUTO_INCREMENT,      -- Identifiant unique
    type_action VARCHAR(50) NOT NULL,                      -- Type de l'action réalisé
    date_debut DATE NOT NULL,                              -- Date du début de l'action obligatoire
    date_fin DATE,                                         -- Date de fin l'action 
    statut VARCHAR(50) NOT NULL CHECK (statut IN ('Planifiée','En cours','Terminée')),
    id_incident INT NOT NULL,                              -- Chaque action est liée à exactement un incident (1..1)
    id_equipe INT NOT NULL,                                -- Chaque action est réalisée par une seule équipe (1..1)
    FOREIGN KEY (id_incident) REFERENCES Incident(id_incident)
        ON DELETE CASCADE
        ON UPDATE CASCADE,
    FOREIGN KEY (id_equipe) REFERENCES Equipes(id_equipe)
        ON DELETE CASCADE
        ON UPDATE CASCADE
);


-- ==============================
-- Tables d'associations (relations N-N)
-- ==============================


-- Menace -> Incident (0..N / 0..N)
CREATE TABLE Provoquer (
    id_menace INT NOT NULL,
    id_incident INT NOT NULL,
    PRIMARY KEY (id_menace, id_incident), 
    FOREIGN KEY (id_menace) REFERENCES Menaces(id_menace) ON DELETE CASCADE ON UPDATE CASCADE,
    FOREIGN KEY (id_incident) REFERENCES Incident(id_incident) ON DELETE CASCADE ON UPDATE CASCADE
);

-- Incident -> Source d’alerte (1..N / 0..N)
CREATE TABLE Est_signale_par (
    id_source INT NOT NULL,
    id_incident INT NOT NULL,
    PRIMARY KEY (id_source, id_incident),
    FOREIGN KEY (id_source) REFERENCES Sources_d_alerte(id_source) ON DELETE CASCADE ON UPDATE CASCADE,
    FOREIGN KEY (id_incident) REFERENCES Incident(id_incident) ON DELETE CASCADE ON UPDATE CASCADE
);

-- Incident -> Actif (1..N / 0..N)
CREATE TABLE Impacter (
    id_actif INT NOT NULL,
    id_incident INT NOT NULL,
    PRIMARY KEY (id_actif, id_incident),
    FOREIGN KEY (id_actif) REFERENCES Actifs(id_actif) ON DELETE CASCADE ON UPDATE CASCADE,
    FOREIGN KEY (id_incident) REFERENCES Incident(id_incident) ON DELETE CASCADE ON UPDATE CASCADE
);

-- Incident -> Équipe (1..N / 0..N)
CREATE TABLE Pris_en_charge (
    id_equipe INT NOT NULL,
    id_incident INT NOT NULL,
    PRIMARY KEY (id_equipe, id_incident),
    FOREIGN KEY (id_equipe) REFERENCES Equipes(id_equipe) ON DELETE CASCADE ON UPDATE CASCADE,
    FOREIGN KEY (id_incident) REFERENCES Incident(id_incident) ON DELETE CASCADE ON UPDATE CASCADE
);

-- Incident -> Vulnérabilité (0..N / 0..N)
CREATE TABLE Concretiser (
    id_vulnerabilite INT NOT NULL,
    id_incident INT NOT NULL,
    PRIMARY KEY (id_vulnerabilite, id_incident),
    FOREIGN KEY (id_vulnerabilite) REFERENCES Vulnerabilites(id_vulnerabilite) ON DELETE CASCADE ON UPDATE CASCADE,
    FOREIGN KEY (id_incident) REFERENCES Incident(id_incident) ON DELETE CASCADE ON UPDATE CASCADE
);
 
--Jeu de données 

-- Table Menaces
INSERT INTO Menaces VALUES
(1,'Ransomware','Chiffrement des données'),
(2,'Phishing','Vol d’identifiants par email'),
(3,'DDoS','Saturation du réseau'),
(4,'Malware','Logiciel malveillant'),
(5,'SQL Injection','Exploitation de failles web'),
(6,'Zero-Day','Vulnérabilité inconnue exploitée'),
(7,'Spyware','Vol d’informations confidentielles'),
(8,'Botnet','Machines compromises coordonnées'),
(9,'Keylogger','Enregistreur de frappes clavier'),
(10,'Trojan','Faux logiciel'),
(11,'Worm','Propagation rapide en réseau'),
(12,'Man-in-the-Middle','Interception de communications'),
(13,'Credential Stuffing','Test massif d’identifiants volés'),
(14,'Brute Force','Tentatives massives de connexion'),
(15,'Rootkit','Prise de contrôle système'),
(16,'Cross-Site Scripting','Injection script sur site web'),
(17,'Backdoor','Accès non autorisé persistant'),
(18,'Supply Chain Attack','Compromission via fournisseur'),
(19,'Insider Threat','Malveillance interne'),
(20,'Cryptojacking','Utilisation illégale des ressources CPU');

-- Table Actifs
INSERT INTO Actifs VALUES
(1,'Paris-SiteA','Serveur','Critique'),
(2,'Paris-SiteA','Base de données','Critique'),
(3,'Paris-SiteA','Réseau','Elevé'),
(4,'Lyon-SiteB','Poste de travail','Moyen'),
(5,'Lyon-SiteB','Serveur','Critique'),
(6,'Lyon-SiteB','Application','Elevé'),
(7,'Marseille-SiteC','Serveur','Critique'),
(8,'Marseille-SiteC','Application','Moyen'),
(9,'Marseille-SiteC','Poste de travail','Faible'),
(10,'Lille-SiteD','Base de données','Critique'),
(11,'Lille-SiteD','Serveur','Elevé'),
(12,'Lille-SiteD','Réseau','Elevé'),
(13,'Toulouse-SiteE','Poste de travail','Moyen'),
(14,'Toulouse-SiteE','Serveur','Critique'),
(15,'Toulouse-SiteE','Application','Elevé'),
(16,'Nantes-SiteF','Serveur','Critique'),
(17,'Nantes-SiteF','Base de données','Critique'),
(18,'Bordeaux-SiteG','Réseau','Critique'),
(19,'Bordeaux-SiteG','Application','Elevé'),
(20,'Bordeaux-SiteG','Poste de travail','Moyen');

-- Table Vulnérabilités
INSERT INTO Vulnerabilites VALUES
(1,'CVE-2021-34527',8.800),
(2,'CVE-2022-1388',9.800),
(3,'CVE-2020-0601',8.100),
(4,'CVE-2017-0144',9.300),
(5,'CVE-2019-0708',9.800),
(6,'CVE-2021-44228',10.000),
(7,'CVE-2018-11776',8.100),
(8,'CVE-2019-3396',8.800),
(9,'CVE-2020-1472',10.000),
(10,'CVE-2021-22986',9.800),
(11,'CVE-2019-11510',9.800),
(12,'CVE-2017-5638',10.000),
(13,'CVE-2019-2725',9.800),
(14,'CVE-2020-5902',10.000),
(15,'CVE-2021-26855',9.800),
(16,'CVE-2021-1675',8.800),
(17,'CVE-2016-0800',7.400),
(18,'CVE-2014-0160',7.500),
(19,'CVE-2015-1635',7.800),
(20,'CVE-2019-19781',9.800);

-- Table Sources_d_alerte
INSERT INTO Sources_d_alerte VALUES
(1,'SIEM','Splunk','Corrélation événements'),
(2,'IDS','Snort','Détection intrusion réseau'),
(3,'Antivirus','Kaspersky','Détection malware poste client'),
(4,'Logs système','Windows Event','Collecte journaux Windows'),
(5,'Firewall','Palo Alto','Blocage trafic suspect'),
(6,'SIEM','ELK Stack','Analyse centralisée logs'),
(7,'IDS','Suricata','Détection trafic réseau'),
(8,'Antivirus','Bitdefender','Détection malware'),
(9,'Logs système','Syslog Linux','Journalisation OS Linux'),
(10,'SIEM','QRadar','Analyse anomalies'),
(11,'NIDS','Zeek','Analyse trafic réseau'),
(12,'EDR','CrowdStrike','Protection endpoint'),
(13,'SIEM','ArcSight','Gestion sécurité'),
(14,'Scanner vulnérabilité','Nessus','Détection failles'),
(15,'WAF','F5','Protection appli web'),
(16,'SIEM','Graylog','Analyse centralisée'),
(17,'IDS','Bro','Analyse comportement réseau'),
(18,'Antivirus','McAfee','Détection virus'),
(19,'Logs système','Sysmon','Monitoring Windows avancé'),
(20,'SIEM','Azure Sentinel','Cloud SIEM');

-- Table Equipes
INSERT INTO Equipes VALUES
(1,'Blue Team','SOC','soc@entreprise.com'),
(2,'Red Team','Pentest','red@entreprise.com'),
(3,'CSIRT','Forensic','csirt@entreprise.com'),
(4,'IT Réseau','Réseau','reseau@entreprise.com'),
(5,'IT Système','Systèmes','systeme@entreprise.com'),
(6,'SOC N1','SOC','socn1@entreprise.com'),
(7,'SOC N2','SOC','socn2@entreprise.com'),
(8,'DFIR','Forensic','dfir@entreprise.com'),
(9,'CTI','Threat Intel','cti@entreprise.com'),
(10,'CERT','Incident Response','cert@entreprise.com'),
(11,'DevSecOps','Cloud Security','devsecops@entreprise.com'),
(12,'Audit','Audit sécurité','audit@entreprise.com'),
(13,'Infra','Infrastructure','infra@entreprise.com'),
(14,'AppSec','Sécurité appli','appsec@entreprise.com'),
(15,'SecOps','Opérations sécurité','secops@entreprise.com'),
(16,'GRC','Conformité','grc@entreprise.com'),
(17,'SOC Cloud','Cloud SOC','soccloud@entreprise.com'),
(18,'CIRT','Cyber Incident Response','cirt@entreprise.com'),
(19,'Purple Team','Off/Def Mix','purple@entreprise.com'),
(20,'Support Sécurité','Support','support@entreprise.com');

-- Table Membre
INSERT INTO Membre VALUES
(1,'Martin','Paul','paul.martin@entreprise.com',123456789,1),
(2,'Dupont','Alice','alice.dupont@entreprise.com',987654321,1),
(3,'Durand','Louis','louis.durand@entreprise.com',147258369,2),
(4,'Moreau','Emma','emma.moreau@entreprise.com',369258147,2),
(5,'Bernard','Lucas','lucas.bernard@entreprise.com',741852963,3),
(6,'Petit','Chloé','chloe.petit@entreprise.com',963852741,3),
(7,'Robert','Léo','leo.robert@entreprise.com',951357456,4),
(8,'Richard','Manon','manon.richard@entreprise.com',456789123,4),
(9,'Durant','Hugo','hugo.durant@entreprise.com',258369147,5),
(10,'Leroy','Sarah','sarah.leroy@entreprise.com',357159456,5),
(11,'Simon','Camille','camille.simon@entreprise.com',654987321,6),
(12,'Fournier','Mathis','mathis.fournier@entreprise.com',321654987,6),
(13,'David','Lina','lina.david@entreprise.com',852741963,7),
(14,'Garnier','Noah','noah.garnier@entreprise.com',753951456,7),
(15,'Roux','Eva','eva.roux@entreprise.com',369147258,8),
(16,'Vincent','Tom','tom.vincent@entreprise.com',147369258,8),
(17,'Henry','Jade','jade.henry@entreprise.com',951456753,9),
(18,'Masson','Clara','clara.masson@entreprise.com',357258159,9),
(19,'Blanc','Adam','adam.blanc@entreprise.com',159357258,10),
(20,'Guerin','Nina','nina.guerin@entreprise.com',258147369,10);


-- Table Incident
INSERT INTO Incident VALUES
(1,'Intrusion','Critique','2025-01-12',NULL,'En cours','Serveur compromis'),
(2,'Fraude','Élevé','2025-01-20','2025-01-22','Résolu','Vol de comptes utilisateurs'),
(3,'Indisponibilité','Critique','2025-01-25',NULL,'En cours','Réseau saturé DDoS'),
(4,'Intrusion','Moyen','2025-02-01','2025-02-02','Résolu','Malware isolé'),
(5,'Fraude','Élevé','2025-02-10',NULL,'En cours','Campagne phishing'),
(6,'Intrusion','Critique','2025-02-15',NULL,'En cours','Exploitation Zero-Day'),
(7,'Propagation','Élevé','2025-02-20','2025-02-21','Résolu','Ver réseau stoppé'),
(8,'Fraude','Moyen','2025-03-01',NULL,'En cours','Keylogger détecté'),
(9,'Intrusion','Élevé','2025-03-05','2025-03-06','Résolu','Injection SQL stoppée'),
(10,'Intrusion','Critique','2025-03-08',NULL,'En cours','Rootkit détecté'),
(11,'Fraude','Moyen','2025-03-15','2025-03-16','Résolu','MITM sur wifi invité'),
(12,'Fraude','Élevé','2025-03-20',NULL,'En cours','Brute force massifs'),
(13,'Intrusion','Critique','2025-03-25',NULL,'En cours','Backdoor trouvée'),
(14,'Intrusion','Critique','2025-03-28',NULL,'En cours','Supply chain compromise'),
(15,'Fraude','Moyen','2025-04-01','2025-04-03','Résolu','Employé malveillant'),
(16,'Fraude','Élevé','2025-04-05',NULL,'En cours','Credential stuffing détecté'),
(17,'Fraude','Critique','2025-04-10',NULL,'En cours','Cryptojacking serveur'),
(18,'Intrusion','Élevé','2025-04-12','2025-04-14','Résolu','XSS exploité'),
(19,'Intrusion','Moyen','2025-04-18',NULL,'En cours','Trojan découvert'),
(20,'Propagation','Critique','2025-04-22',NULL,'En cours','Worm en propagation');

-- Table Actions_Correctives
INSERT INTO Actions_Correctives VALUES
(1,'Isolation système','2025-01-12','2025-01-13','Terminée',1,1),
(2,'Blocage IP','2025-01-20','2025-01-20','Terminée',2,1),
(3,'Reconfiguration firewall','2025-01-25',NULL,'En cours',3,4),
(4,'Suppression malware','2025-02-01','2025-02-01','Terminée',4,5),
(5,'Campagne sensibilisation','2025-02-10',NULL,'Planifiée',5,12),
(6,'Patch Zero-Day','2025-02-15',NULL,'En cours',6,11),
(7,'Blocage propagation','2025-02-20','2025-02-21','Terminée',7,4),
(8,'Suppression keylogger','2025-03-01',NULL,'En cours',8,5),
(9,'Blocage requêtes SQL','2025-03-05','2025-03-05','Terminée',9,14),
(10,'Nettoyage rootkit','2025-03-08',NULL,'En cours',10,3),
(11,'Chiffrement WPA2','2025-03-15','2025-03-16','Terminée',11,4),
(12,'Blocage IP brute force','2025-03-20',NULL,'En cours',12,1),
(13,'Suppression backdoor','2025-03-25',NULL,'En cours',13,3),
(14,'Audit fournisseurs','2025-03-28',NULL,'En cours',14,12),
(15,'Licenciement employé','2025-04-01','2025-04-02','Terminée',15,16),
(16,'Blocage IP credential stuffing','2025-04-05',NULL,'En cours',16,1),
(17,'Suppression cryptominer','2025-04-10',NULL,'En cours',17,5),
(18,'Correction faille XSS','2025-04-12','2025-04-13','Terminée',18,14),
(19,'Suppression trojan','2025-04-18',NULL,'En cours',19,5),
(20,'Blocage worm','2025-04-22',NULL,'En cours',20,4);


-- Table Provoquer (Menaces ↔ Incident) 
INSERT INTO Provoquer VALUES 
(1,1),(2,2),(3,3),(4,4),(2,5), 
(6,6),(11,7),(9,8),(5,9),(15,10), 
(12,11),(14,12),(17,13),(18,14),(19,15), 
(13,16),(20,17),(16,18),(10,19),(11,20);

-- Table Impacte (Actifs ↔ Incident)
INSERT INTO Impacter VALUES
(1,1),(2,1),(3,3),(5,3),(6,4),
(7,6),(8,6),(9,8),(10,9),(11,10),
(12,11),(13,12),(14,13),(15,14),(16,15),
(17,16),(18,17),(19,18),(20,19),(4,20);

-- Table Est_signalé_par (Sources_d_alerte ↔ Incident)
INSERT INTO Est_signale_par VALUES
(1,1),(2,1),(3,2),(4,2),(5,3),
(6,3),(7,4),(8,4),(9,5),(10,6),
(11,7),(12,8),(13,9),(14,10),(15,11),
(16,12),(17,13),(18,14),(19,15),(20,16);

-- Table Pris_en_charge (Equipes ↔ Incident)
INSERT INTO Pris_en_charge VALUES
(1,1),(3,1),(1,2),(12,2),(4,3),
(6,3),(5,4),(11,6),(8,6),(4,7),
(5,8),(14,9),(3,10),(4,11),(1,12),
(3,13),(12,14),(16,15),(1,16),(5,17);

-- Table Concretiser (Vulnérabilités ↔ Incident)
INSERT INTO Concretiser VALUES
(1,1),(2,2),(3,3),(4,4),(5,5),
(6,6),(7,7),(8,8),(9,9),(10,10),
(11,11),(12,12),(13,13),(14,14),(15,15),
(16,16),(17,17),(18,18),(19,19),(20,20);

