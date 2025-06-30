// Simple test script to verify our security scanner
import { securityScanner } from './src/services/securityScanner.js';

async function testScanner() {
  console.log('🔍 Test du scanner de sécurité...\n');
  
  const testUrls = [
    'https://example.com',
    'https://google.com',
    'https://github.com'
  ];

  for (const url of testUrls) {
    console.log(`📊 Analyse de: ${url}`);
    try {
      const result = await securityScanner.scanWebsite(url);
      console.log(`✅ Score: ${result.score}/100`);
      console.log(`🔍 Vulnérabilités trouvées: ${result.vulnerabilities.length}`);
      
      if (result.vulnerabilities.length > 0) {
        result.vulnerabilities.forEach((vuln, index) => {
          console.log(`   ${index + 1}. [${vuln.severity.toUpperCase()}] ${vuln.type}`);
        });
      }
      console.log('');
    } catch (error) {
      console.log(`❌ Erreur: ${error.message}\n`);
    }
  }
}

testScanner().catch(console.error);
