// Test du nouveau système de scoring
console.log('🧪 Test du Nouveau Système de Scoring\n');

// Simulation de la fonction calculateScore
function calculateScore(vulnerabilities) {
  let score = 100;
  vulnerabilities.forEach(vuln => {
    if (vuln.severity === 'critical') score -= 20;
    else if (vuln.severity === 'high') score -= 15;
    else if (vuln.severity === 'medium') score -= 10;
    else if (vuln.severity === 'low') score -= 5;
    // info = 0 points
  });
  return Math.max(0, Math.min(100, score));
}

// Ancien système pour comparaison
function calculateScoreOld(vulnerabilities) {
  let score = 100;
  vulnerabilities.forEach(vuln => {
    if (vuln.severity === 'critical') score -= 25;
    else if (vuln.severity === 'high') score -= 15;
    else if (vuln.severity === 'medium') score -= 8;
    else if (vuln.severity === 'low') score -= 3;
  });
  return Math.max(0, Math.min(100, score));
}

// Scénarios de test
const scenarios = [
  {
    name: "Site très sécurisé",
    vulnerabilities: [
      { severity: 'info' },
      { severity: 'info' },
      { severity: 'low' }
    ]
  },
  {
    name: "Site moyennement sécurisé",
    vulnerabilities: [
      { severity: 'medium' },
      { severity: 'medium' },
      { severity: 'low' },
      { severity: 'low' },
      { severity: 'info' }
    ]
  },
  {
    name: "Site avec problèmes importants",
    vulnerabilities: [
      { severity: 'high' },
      { severity: 'high' },
      { severity: 'medium' },
      { severity: 'medium' },
      { severity: 'medium' },
      { severity: 'low' }
    ]
  },
  {
    name: "Site critique",
    vulnerabilities: [
      { severity: 'critical' },
      { severity: 'high' },
      { severity: 'high' },
      { severity: 'medium' },
      { severity: 'medium' },
      { severity: 'low' },
      { severity: 'low' }
    ]
  },
  {
    name: "Site avec beaucoup d'infos",
    vulnerabilities: [
      { severity: 'info' },
      { severity: 'info' },
      { severity: 'info' },
      { severity: 'info' },
      { severity: 'info' },
      { severity: 'medium' },
      { severity: 'low' }
    ]
  }
];

console.log('📊 Comparaison Ancien vs Nouveau Système\n');
console.log('Scénario'.padEnd(30) + 'Ancien'.padEnd(10) + 'Nouveau'.padEnd(10) + 'Différence');
console.log('-'.repeat(60));

scenarios.forEach(scenario => {
  const oldScore = calculateScoreOld(scenario.vulnerabilities);
  const newScore = calculateScore(scenario.vulnerabilities);
  const difference = newScore - oldScore;
  const diffStr = difference > 0 ? `+${difference}` : `${difference}`;
  
  console.log(
    scenario.name.padEnd(30) + 
    `${oldScore}/100`.padEnd(10) + 
    `${newScore}/100`.padEnd(10) + 
    diffStr
  );
});

console.log('\n📈 Analyse des Changements:');
console.log('• Les scores "info" restent inchangés (100/100)');
console.log('• Les vulnérabilités medium ont plus d\'impact (-10 vs -8)');
console.log('• Les vulnérabilités low ont plus d\'impact (-5 vs -3)');
console.log('• Les vulnérabilités critical ont moins d\'impact (-20 vs -25)');
console.log('• Progression plus linéaire et équilibrée');

console.log('\n✅ Le nouveau système offre:');
console.log('• Des scores plus réalistes');
console.log('• Une progression logique (5 points d\'écart)');
console.log('• Moins de scores extrêmement bas');
console.log('• Une meilleure motivation pour les utilisateurs');
