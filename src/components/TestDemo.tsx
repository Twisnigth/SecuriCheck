import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Play, CheckCircle, AlertTriangle, XCircle } from "lucide-react";
import { securityScanner } from "@/services/securityScanner";

const TestDemo = () => {
  const [isRunning, setIsRunning] = useState(false);
  const [testResults, setTestResults] = useState<any[]>([]);

  const testSites = [
    { url: "https://example.com", name: "Example.com" },
    { url: "https://google.com", name: "Google" },
    { url: "https://github.com", name: "GitHub" },
  ];

  const runTests = async () => {
    setIsRunning(true);
    setTestResults([]);
    
    for (const site of testSites) {
      try {
        const result = await securityScanner.scanWebsite(site.url);
        setTestResults(prev => [...prev, {
          ...site,
          result,
          status: 'success'
        }]);
      } catch (error) {
        setTestResults(prev => [...prev, {
          ...site,
          error: error instanceof Error ? error.message : 'Erreur inconnue',
          status: 'error'
        }]);
      }
    }
    
    setIsRunning(false);
  };

  const getScoreColor = (score: number) => {
    if (score >= 80) return "bg-green-500";
    if (score >= 60) return "bg-yellow-500";
    return "bg-red-500";
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'success': return <CheckCircle className="h-4 w-4 text-green-500" />;
      case 'error': return <XCircle className="h-4 w-4 text-red-500" />;
      default: return <AlertTriangle className="h-4 w-4 text-yellow-500" />;
    }
  };

  return (
    <Card className="w-full max-w-4xl mx-auto mt-8 bg-white/10 backdrop-blur-sm border-white/20">
      <CardHeader>
        <CardTitle className="text-white flex items-center space-x-2">
          <Play className="h-5 w-5" />
          <span>Démonstration du Scanner</span>
        </CardTitle>
        <CardDescription className="text-slate-300">
          Testez le scanner avec des sites web populaires pour voir les fonctionnalités en action
        </CardDescription>
      </CardHeader>
      <CardContent>
        <Button 
          onClick={runTests} 
          disabled={isRunning}
          className="mb-6 bg-purple-600 hover:bg-purple-700"
        >
          {isRunning ? "Tests en cours..." : "Lancer les tests de démonstration"}
        </Button>

        {testResults.length > 0 && (
          <div className="space-y-4">
            <h4 className="text-lg font-medium text-white">Résultats des tests :</h4>
            {testResults.map((test, index) => (
              <div key={index} className="p-4 bg-white/5 rounded-lg border border-white/10">
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center space-x-2">
                    {getStatusIcon(test.status)}
                    <span className="text-white font-medium">{test.name}</span>
                    <span className="text-slate-400 text-sm">({test.url})</span>
                  </div>
                  {test.result && (
                    <Badge className={`${getScoreColor(test.result.score)} text-white`}>
                      {test.result.score}/100
                    </Badge>
                  )}
                </div>
                
                {test.result && (
                  <div className="text-sm text-slate-300">
                    <p>Vulnérabilités détectées: {test.result.vulnerabilities.length}</p>
                    {test.result.vulnerabilities.slice(0, 3).map((vuln: any, vIndex: number) => (
                      <p key={vIndex} className="ml-4 text-xs">
                        • [{vuln.severity.toUpperCase()}] {vuln.type}
                      </p>
                    ))}
                    {test.result.vulnerabilities.length > 3 && (
                      <p className="ml-4 text-xs text-slate-400">
                        ... et {test.result.vulnerabilities.length - 3} autres
                      </p>
                    )}
                  </div>
                )}
                
                {test.error && (
                  <p className="text-red-300 text-sm">Erreur: {test.error}</p>
                )}
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
};

export default TestDemo;
