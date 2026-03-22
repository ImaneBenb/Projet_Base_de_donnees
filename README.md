# Projet de Base de Données

## Description

Ce projet est une base de données conçue pour gérer et suivre les incidents de cybersécurité. Elle permet de centralisée de recenser, classifier et corréler les incidents de sécurité.

## Schéma de la base de données

La base de données est composée des tables suivantes :

*   **Menaces**: Contient des informations sur les différents types de menaces de cybersécurité
*   **Actifs**: Répertorie les différents actifs qui peuvent être affecté par un incident 
*   **Vulnerabilites**: Répertorie les vulnérabilités qui peuvent causer des incidents 
*   **Sources_d_alerte**: Contient des informations sur les sources qui signalent les incidents
*   **Equipes**: Répertorie les équipes de sécurité qui s’occupent des incidents
*   **Incident**: Répertorie les incidents 
*   **Membre**: Contient les informations sur les membres des équipes de sécurité
*   **Actions_Correctives**: Suit les actions prises pour résoudre les incidents

Des tables d'association sont également utilisées pour gérer les relations entre les tables principales.

## Fichiers

*   `ScriptSQL.sql`: Ce fichier contient le script SQL pour créer la structure de la base de données et insérer des données d'exemple
*   `Requetes_VuesSQL.sql`: Ce fichier contient le script d'implémentation des données pour alimenter les tables et de vues de la base de données
*   `Rapport_projet_BDD---.pdf`: Rapport de projet
*   `HTML_CSS_PHP.zip`: Contient le site web permettant de visionner quelques informations présentes dans la BDD pour l'équipe de SOC
*   `Association.loo`: les schéma MCD et MLD de la base de données ouvrable avec le logiciel Looping.

## Comment utiliser

1.  Utilisez le fichier `ScriptSQL.sql` pour créer la base de données dans votre système de gestion de base de données (par exemple : MySQL, PostgreSQL...).
2.  Utiliser les requêtes dans `Requetes_VuesSQL.sql` pour remplir la base de données
3.  

Vous pourrez trouver le rapport de projet sous le nom de "Rapport_projet_BDD---.pdf".

Le script d'ajout des tables pour la base de données s'appelle "ScriptSQL.sql".
Le script d'implémentation des données pour alimenter les tables s'appelle "Requetes_VuesSQL.sql".

Le site web permettant de visionner quelques informations présentes dans la BDD pour l'équipe de SOC se trouve dans le dossier sous format zip "HTML_CSS_PHP.zip".

Pour finir, le schéma MCD et MLD sont trouvables dans le fichier "Association.loo" ouvrable avec le logiciel Looping.

Cordialement,
DIARRA Mamadou
BENBOUZIANE Imane
