// Test script pour vérifier le nouveau système de classification
import { securityScanner } from './src/services/securityScanner.js';

async function testClassification() {
  console.log('🔍 Test du nouveau système de classification des vulnérabilités...\n');
  
  try {
    // Test avec un site qui aura probablement des vulnérabilités
    const testUrl = 'http://example.com';
    console.log(`📊 Analyse de ${testUrl}...`);
    
    const result = await securityScanner.scanWebsite(testUrl);
    
    console.log('\n📋 Résultats de l\'analyse:');
    console.log(`Score de sécurité: ${result.score}/100`);
    console.log(`Nombre de vulnérabilités: ${result.vulnerabilities.length}`);
    
    // Grouper les vulnérabilités par sévérité
    const vulnBySeverity = result.vulnerabilities.reduce((acc, vuln) => {
      acc[vuln.severity] = (acc[vuln.severity] || 0) + 1;
      return acc;
    }, {});
    
    console.log('\n🎯 Répartition par sévérité:');
    const severityOrder = ['critical', 'high', 'medium', 'low', 'info'];
    severityOrder.forEach(severity => {
      if (vulnBySeverity[severity]) {
        const emoji = {
          critical: '🔴',
          high: '🟠', 
          medium: '🟡',
          low: '🔵',
          info: '⚪'
        }[severity];
        console.log(`${emoji} ${severity.toUpperCase()}: ${vulnBySeverity[severity]} vulnérabilité(s)`);
      }
    });
    
    console.log('\n💡 Conseils personnalisés générés:');
    if (result.personalizedAdvice && result.personalizedAdvice.length > 0) {
      result.personalizedAdvice.slice(0, 5).forEach((advice, index) => {
        console.log(`${index + 1}. ${advice}`);
      });
      if (result.personalizedAdvice.length > 5) {
        console.log(`... et ${result.personalizedAdvice.length - 5} autres conseils`);
      }
    } else {
      console.log('Aucun conseil personnalisé généré');
    }
    
    console.log('\n✅ Test terminé avec succès !');
    
  } catch (error) {
    console.error('❌ Erreur lors du test:', error.message);
  }
}

// Exécuter le test
testClassification();
