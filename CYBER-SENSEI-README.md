# Cyber Sensei Tool - Scanner de Sécurité Web

Un scanner de sécurité web moderne construit avec React, TypeScript, et Vite. Cet outil permet d'analyser les vulnérabilités de sécurité d'un site web et de générer un rapport PDF téléchargeable.

## 🚀 Fonctionnalités

- **Analyse de sécurité complète** : Vérification des headers HTTP, méthodes autorisées, certificats SSL
- **Génération de PDF** : Création automatique de rapports de sécurité professionnels
- **Interface moderne** : Design responsive avec Tailwind CSS et shadcn/ui
- **Validation d'URL** : Vérification et normalisation automatique des URLs
- **Gestion d'erreurs** : Traitement intelligent des erreurs CORS et de réseau
- **Démonstration intégrée** : Tests automatiques avec des sites populaires

## 🔍 Types de vulnérabilités détectées

### Headers de sécurité manquants
- **Content-Security-Policy (CSP)** : Prévient les attaques XSS et injection de code
- **X-Frame-Options** : Protège contre les attaques de clickjacking
- **Strict-Transport-Security (HSTS)** : Force l'utilisation de HTTPS
- **X-Content-Type-Options** : Empêche le MIME type sniffing
- **X-XSS-Protection** : Active la protection XSS du navigateur

### Méthodes HTTP
- Détection des méthodes potentiellement dangereuses (PUT, DELETE, PATCH, TRACE)
- Vérification de la méthode TRACE (vulnérable aux attaques XST)

### Sécurité SSL/TLS
- Vérification de l'utilisation d'HTTPS
- Détection des certificats expirés ou invalides

### Exposition d'informations
- Headers révélant des informations sur le serveur
- Technologies exposées via X-Powered-By

## 📋 Utilisation

1. **Saisir l'URL** : Entrez l'URL du site à analyser dans le champ prévu
2. **Lancer l'analyse** : Cliquez sur "Lancer l'analyse" pour démarrer le scan
3. **Consulter les résultats** : Visualisez les vulnérabilités détectées avec leur niveau de sévérité
4. **Télécharger le rapport** : Cliquez sur "Exporter PDF" pour obtenir un rapport détaillé

## 🛠 Architecture technique

### Services principaux

#### SecurityScanner (`src/services/securityScanner.ts`)
- Effectue les vérifications de sécurité HTTP
- Analyse les headers de sécurité
- Vérifie les méthodes HTTP autorisées
- Contrôle les certificats SSL/TLS
- Calcule un score de sécurité global

#### PDFGenerator (`src/services/pdfGenerator.ts`)
- Génère des rapports PDF professionnels
- Mise en page avec en-têtes et pieds de page
- Coloration selon la sévérité des vulnérabilités
- Recommandations de sécurité intégrées

#### URLValidator (`src/utils/urlValidator.ts`)
- Validation et normalisation des URLs
- Vérification des domaines publics
- Gestion des protocoles HTTP/HTTPS

### Composants React

#### Index (`src/pages/Index.tsx`)
- Interface principale de l'application
- Gestion des états de scan
- Intégration de la validation et de l'analyse

#### ScanResults (`src/components/ScanResults.tsx`)
- Affichage des résultats d'analyse
- Bouton de téléchargement PDF
- Visualisation des vulnérabilités par sévérité

#### TestDemo (`src/components/TestDemo.tsx`)
- Démonstration avec des sites populaires
- Tests automatisés pour validation

## 🎨 Design et UX

- **Interface sombre** : Thème cybersécurité avec dégradés purple/slate
- **Responsive** : Adaptation automatique aux différentes tailles d'écran
- **Feedback visuel** : Indicateurs de chargement et messages d'erreur
- **Accessibilité** : Couleurs contrastées et navigation au clavier

## 🔧 Installation et développement

```bash
# Installation des dépendances
npm install

# Démarrage du serveur de développement
npm run dev

# Build de production
npm run build
```

## 📦 Dépendances principales

- **React 18** : Framework frontend
- **TypeScript** : Typage statique
- **Vite** : Build tool et dev server
- **Tailwind CSS** : Framework CSS utilitaire
- **shadcn/ui** : Composants UI modernes
- **jsPDF** : Génération de PDF
- **Axios** : Client HTTP
- **Lucide React** : Icônes

## 🚨 Limitations et considérations

### Limitations CORS
- Les navigateurs bloquent certaines requêtes cross-origin
- Certains sites peuvent ne pas être analysables depuis le navigateur
- Les erreurs CORS sont traitées comme des bonnes pratiques de sécurité

### Analyse passive
- L'outil effectue uniquement des analyses non-destructives
- Aucune tentative d'exploitation des vulnérabilités
- Adapté pour l'apprentissage et la sensibilisation

## 🎓 Utilisation pédagogique

Cet outil est conçu spécialement pour les étudiants en cybersécurité :

- **Apprentissage pratique** : Compréhension des vulnérabilités web courantes
- **Sensibilisation** : Importance des headers de sécurité
- **Bonnes pratiques** : Recommandations pour sécuriser les applications web
- **Rapports détaillés** : Explications pédagogiques pour chaque vulnérabilité

## 📈 Évolutions futures

- Support de plus de types de vulnérabilités
- Analyse des cookies et de leur sécurité
- Vérification des politiques de sécurité avancées
- Intégration d'APIs de threat intelligence
- Mode batch pour analyser plusieurs sites

## 🤝 Contribution

Ce projet est ouvert aux contributions pour améliorer les fonctionnalités d'analyse et l'expérience utilisateur.

## 📄 Licence

Projet éducatif - Version étudiante
