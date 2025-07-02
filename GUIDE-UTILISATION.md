# Guide d'Utilisation du Nouveau Système de Classification

## 🎯 Comment Utiliser les Améliorations

### 1. Lancement de l'Application
```bash
npm run dev
```
L'application sera accessible sur `http://localhost:8081`

### 2. Analyse d'un Site Web
1. Entrez l'URL du site à analyser
2. Cliquez sur "Analyser"
3. Attendez les résultats

### 3. Interprétation des Résultats

#### Niveaux de Sévérité
- **🔴 CRITICAL** : À corriger IMMÉDIATEMENT - Vulnérabilités facilement exploitables
- **🟠 HIGH** : À corriger en PRIORITÉ - Vulnérabilités exploitables importantes  
- **🟡 MEDIUM** : À corriger rapidement - Vulnérabilités exploitables modérées
- **🔵 LOW** : À corriger quand possible - Vulnérabilités mineures
- **⚪ INFO** : Informatif seulement - Non exploitable, n'affecte pas le score

#### Score de Sécurité
- **90-100** : Excellente sécurité
- **80-89** : Bonne sécurité  
- **70-79** : Sécurité correcte, améliorations recommandées
- **60-69** : Sécurité insuffisante, corrections nécessaires
- **0-59** : Sécurité critique, action urgente requise

### 4. Conseils Personnalisés
Les conseils sont générés automatiquement en fonction des vulnérabilités détectées :

#### Types de Conseils
- **🚨 Priorité Absolue** : Pour les vulnérabilités critiques
- **⚠️ Haute Priorité** : Pour les vulnérabilités high
- **📋 Configuration** : Pour les headers manquants
- **🍪 Cookies** : Pour la sécurité des cookies
- **🛡️ CSRF** : Pour la protection des formulaires
- **🔒 Confidentialité** : Pour la divulgation d'informations
- **🌐 HTTP** : Pour les méthodes et protocoles

### 5. Génération de Rapport PDF
1. Cliquez sur "Exporter PDF" après l'analyse
2. Le PDF inclut :
   - Résumé de l'analyse avec score
   - Vulnérabilités triées par sévérité
   - Conseils personnalisés détaillés
   - Recommandations d'actions

## 🔍 Exemples Pratiques

### Exemple 1 : Site avec Vulnérabilités Critiques
```
Score : 45/100
Vulnérabilités :
🔴 CRITICAL (2) : CSP avec unsafe-eval, Injection SQL
🟠 HIGH (3) : HTTPS manquant, CSP manquante, Certificat expiré
🟡 MEDIUM (5) : Headers manquants
⚪ INFO (2) : Informations serveur exposées

Conseils :
🚨 PRIORITÉ ABSOLUE : Corrections immédiates requises
• Éliminer unsafe-eval de la CSP
• Corriger les vulnérabilités d'injection SQL
⚠️ HAUTE PRIORITÉ : Implémenter HTTPS et CSP
```

### Exemple 2 : Site Bien Sécurisé
```
Score : 92/100
Vulnérabilités :
🔵 LOW (1) : Referrer-Policy manquant
⚪ INFO (2) : Informations serveur exposées

Conseils :
🟢 Excellente sécurité : Quelques améliorations mineures possibles
• Ajouter Referrer-Policy pour une protection complète
• Masquer les informations serveur (optionnel)
```

## 📊 Comparaison Avant/Après

### Ancien Système
- 4 niveaux : low, medium, high, best-practice
- Toutes les vulnérabilités affectaient le score
- Recommandations génériques
- Pas de priorisation claire

### Nouveau Système  
- 5 niveaux : info, low, medium, high, critical
- Seules les vulnérabilités exploitables affectent le score
- Conseils personnalisés et contextuels
- Priorisation claire des actions

## 🚀 Conseils d'Utilisation

1. **Priorisez toujours** les vulnérabilités CRITICAL et HIGH
2. **Ignorez temporairement** les vulnérabilités INFO si vous avez des priorités plus élevées
3. **Utilisez les conseils personnalisés** comme guide d'action
4. **Testez régulièrement** votre site après les corrections
5. **Exportez les rapports PDF** pour le suivi et la documentation

## 🔧 Dépannage

### Problèmes Courants
- **Erreur de connexion** : Vérifiez que l'URL est accessible
- **Timeout** : Le site peut être lent à répondre
- **Pas de vulnérabilités** : Le site peut être très bien sécurisé

### Support
- Consultez les logs de la console pour plus de détails
- Vérifiez la connectivité réseau
- Testez avec des URLs simples d'abord (ex: http://example.com)
