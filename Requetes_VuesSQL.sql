-- ==============================
-- Requêtes SQL
-- ==============================

-- Lister les incidents critiques non résolus :
SELECT id_Incident, type_incident FROM incident 
WHERE niveau_gravite = 'Critique' AND statut <> 'Résolu';

-- Identifier les actifs les plus attaqués au cours d’une période donnée : 
SELECT A.type_actif, COUNT(I.id_Incident) AS actif_plus_attaque 
FROM Actifs A 
JOIN Impacter IM ON A.id_actif = IM.id_actif 
JOIN Incident I ON IM.id_Incident = I.id_Incident 
WHERE I.date_detection >= '2025-03-06' 
GROUP BY A.type_actif
ORDER BY actif_plus_attaque DESC;

-- Calculer le temps moyen de résolution des incidents par équipe : 
SELECT E.id_equipe, E.nom_equipe, AVG(I.date_resolution - I.date_detection) AS delai_moyen_resolution 
FROM Equipes E JOIN Pris_en_charge P ON E.id_equipe = P.id_equipe 
JOIN Incident I ON P.id_Incident = I.id_Incident 
WHERE I.statut = 'Résolu' 
GROUP BY E.id_equipe, E.nom_equipe 
ORDER BY delai_moyen_resolution;

-- Corréler les incidents avec les vulnérabilités connues (CVE) : 
SELECT I.id_Incident, I.type_incident, V.id_vulnerabilite, V.CVE FROM Incident I 
JOIN Concretiser C ON I.id_Incident = C.id_Incident 
JOIN Vulnerabilites V ON C.id_vulnerabilite = V.id_vulnerabilite 
ORDER BY I.date_detection DESC;


-- ==============================
-- Vues SQL 
-- ==============================


-- Nombre d’incident par niveau de gravité 
CREATE VIEW vue_incidents_par_gravite AS 
SELECT COUNT(id_Incident) AS nb_incidents, niveau_gravite FROM Incident 
GROUP BY niveau_gravite 
ORDER BY nb_incidents DESC;

-- Nombre d’incident par type de menace 
CREATE VIEW vue_incidents_par_menace AS 
SELECT M.nom_menace, COUNT(P.id_Incident) AS nb_incidents 
FROM Menaces M 
JOIN Provoquer P ON M.id_menace = P.id_menace 
GROUP BY M.nom_menace 
ORDER BY nb_incidents DESC;

-- Actifs les plus attaqués 
CREATE VIEW vue_actifs_plus_attaques AS 
SELECT A.type_actif, COUNT(I.id_Incident) AS actif_plus_attaque 
FROM Actifs A 
JOIN Impacter IM ON A.id_actif = IM.id_actif 
JOIN Incident I ON IM.id_Incident = I.id_Incident 
GROUP BY A.type_actif 
ORDER BY actif_plus_attaque DESC;

-- Incidents liés aux vulnérabilités 
CREATE VIEW vue_incident_lies_aux_vulnerabilites AS 
SELECT V.CVE, V.CVSS_Score, COUNT(I.id_Incident) AS nb_incidents 
FROM Incident I 
JOIN Concretiser C ON I.id_Incident = C.id_Incident 
JOIN Vulnerabilites V ON C.id_vulnerabilite = V.id_vulnerabilite 
GROUP BY V.CVE, V.CVSS_Score
ORDER BY nb_incidents DESC;

-- Temps moyen de résolution des incidents 
CREATE VIEW vue_temps_moyen_resolution_incident AS 
SELECT AVG(date_resolution - date_detection) AS delai_moyen_resolution_en_jour 
FROM Incident 
WHERE statut = 'Résolu' 
ORDER BY delai_moyen_resolution_en_jour;

-- Temps moyen de résolution des incidents par équipe 
CREATE VIEW vue_temps_moyen_resolution_incident_par_equipe AS 
SELECT E.id_equipe, E.nom_equipe, AVG(I.date_resolution - I.date_detection) AS delai_moyen_resolution FROM Equipes E 
JOIN Pris_en_charge P ON E.id_equipe = P.id_equipe 
JOIN Incident I ON P.id_Incident = I.id_Incident 
WHERE I.statut = 'Résolu'
GROUP BY E.id_equipe, E.nom_equipe 
ORDER BY delai_moyen_resolution;

-- Actions correctives par statut 
CREATE VIEW vue_action_par_statut AS 
SELECT statut, COUNT(id_action) AS nb_actions 
FROM actions_correctives 
GROUP BY statut 
ORDER BY nb_actions DESC;

-- Incident par source d’alerte 
CREATE VIEW vue_incidents_par_source_d_alerte AS 
SELECT S.type_source, COUNT(E.id_Incident) AS nb_incidents 
FROM sources_d_alerte S 
JOIN est_signale_par E ON S.id_source = E.id_source 
GROUP BY S.type_source 
ORDER BY nb_incidents DESC;

-- Incidents non résolu 
CREATE VIEW vue_incident_non_resolu AS 
SELECT id_Incident, type_incident, niveau_gravite, date_detection 
FROM incident 
WHERE statut <> 'Résolu' 
ORDER BY date_detection;
