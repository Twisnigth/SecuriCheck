
import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Shield, Globe, AlertTriangle, CheckCircle, Loader2 } from "lucide-react";
import ScanResults from "@/components/ScanResults";
import { securityScanner, ScanResult } from "@/services/securityScanner";
import { validateUrl } from "@/utils/urlValidator";

const Index = () => {
  const [url, setUrl] = useState("");
  const [isScanning, setIsScanning] = useState(false);
  const [scanComplete, setScanComplete] = useState(false);
  const [scanResults, setScanResults] = useState<ScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleScan = async () => {
    if (!url) return;

    // Validate URL
    const validation = validateUrl(url);
    if (!validation.isValid) {
      setError(validation.error || 'URL invalide');
      return;
    }

    setIsScanning(true);
    setScanComplete(false);
    setError(null);

    try {
      const results = await securityScanner.scanWebsite(validation.normalizedUrl!);
      setScanResults(results);
      setScanComplete(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Une erreur est survenue lors de l\'analyse');
      console.error('Erreur lors du scan:', err);
    } finally {
      setIsScanning(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900 font-inter">
      {/* Header */}
      <div className="container mx-auto px-6 py-8">
        <div className="flex items-center justify-between mb-12">
          <div className="flex items-center space-x-3">
            <Shield className="h-8 w-8 text-purple-400" />
            <h1 className="text-2xl font-semibold text-white">Scanner de Vulnérabilités Web</h1>
          </div>
          <div className="bg-purple-600 text-white px-4 py-2 rounded-lg text-sm font-medium">
            Version Étudiante
          </div>
        </div>

        {/* Hero Section */}
        <div className="text-center mb-16">
          <h2 className="text-5xl font-light text-white mb-6 leading-tight">
            Protégez le Monde
            <br />
            <span className="text-6xl font-normal">Numérique</span>
          </h2>
          <p className="text-xl text-slate-300 max-w-2xl mx-auto mb-8">
            Analysez la sécurité de vos projets web étudiants avec notre outil pédagogique. 
            Détectez les vulnérabilités courantes et apprenez les bonnes pratiques.
          </p>
        </div>

        {/* Scan Form */}
        <div className="max-w-2xl mx-auto mb-12">
          <div className="bg-white/10 backdrop-blur-sm rounded-2xl p-8 border border-white/20">
            <div className="flex items-center space-x-3 mb-6">
              <Globe className="h-6 w-6 text-purple-400" />
              <h3 className="text-xl font-medium text-white">Analyser un Site Web</h3>
            </div>
            
            <div className="space-y-4">
              <div>
                <Label htmlFor="url" className="text-white mb-2 block">
                  URL du site à analyser
                </Label>
                <Input
                  id="url"
                  type="url"
                  placeholder="https://exemple.com"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  className="bg-white/20 border-white/30 text-white placeholder:text-slate-400 focus:bg-white/25"
                />
              </div>
              
              <Button 
                onClick={handleScan}
                disabled={!url || isScanning}
                className="w-full bg-purple-600 hover:bg-purple-700 text-white py-3 text-lg font-medium"
              >
                {isScanning ? (
                  <>
                    <Loader2 className="h-5 w-5 mr-2 animate-spin" />
                    Analyse en cours...
                  </>
                ) : (
                  <>
                    <Shield className="h-5 w-5 mr-2" />
                    Lancer l'analyse
                  </>
                )}
              </Button>
            </div>

            {isScanning && (
              <div className="mt-6 p-4 bg-blue-500/20 rounded-lg border border-blue-400/30">
                <div className="flex items-center space-x-3">
                  <Loader2 className="h-5 w-5 text-blue-400 animate-spin" />
                  <div>
                    <p className="text-blue-200 font-medium">Analyse de sécurité en cours...</p>
                    <p className="text-blue-300 text-sm">Vérification des headers, méthodes HTTP et vulnérabilités courantes</p>
                  </div>
                </div>
              </div>
            )}

            {error && (
              <div className="mt-6 p-4 bg-red-500/20 rounded-lg border border-red-400/30">
                <div className="flex items-center space-x-3">
                  <AlertTriangle className="h-5 w-5 text-red-400" />
                  <div>
                    <p className="text-red-200 font-medium">Erreur lors de l'analyse</p>
                    <p className="text-red-300 text-sm">{error}</p>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Results */}
        {scanComplete && scanResults && (
          <ScanResults results={scanResults} />
        )}

        {/* Features */}
        <div className="grid md:grid-cols-3 gap-8 mt-16">
          <div className="text-center p-6">
            <div className="bg-green-500/20 w-16 h-16 rounded-full flex items-center justify-center mx-auto mb-4">
              <CheckCircle className="h-8 w-8 text-green-400" />
            </div>
            <h4 className="text-xl font-medium text-white mb-2">Analyse Non-Destructive</h4>
            <p className="text-slate-300">Tests passifs qui n'affectent pas votre site</p>
          </div>
          
          <div className="text-center p-6">
            <div className="bg-blue-500/20 w-16 h-16 rounded-full flex items-center justify-center mx-auto mb-4">
              <Globe className="h-8 w-8 text-blue-400" />
            </div>
            <h4 className="text-xl font-medium text-white mb-2">Rapport Détaillé</h4>
            <p className="text-slate-300">Explications pédagogiques pour chaque vulnérabilité</p>
          </div>
          
          <div className="text-center p-6">
            <div className="bg-purple-500/20 w-16 h-16 rounded-full flex items-center justify-center mx-auto mb-4">
              <AlertTriangle className="h-8 w-8 text-purple-400" />
            </div>
            <h4 className="text-xl font-medium text-white mb-2">Apprentissage</h4>
            <p className="text-slate-300">Conçu spécialement pour les étudiants</p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Index;
