import { AlertTriangle, CheckCircle, XCircle, Download, Shield } from "lucide-react";
import { Button } from "@/components/ui/button";
import { pdfGenerator } from "@/services/pdfGenerator";
import { ScanResult } from "@/services/securityScanner";

interface ScanResultsProps {
  results: ScanResult;
}

const ScanResults = ({ results }: ScanResultsProps) => {
  const handleDownloadPDF = () => {
    pdfGenerator.downloadPDF(results);
  };

  // Sort vulnerabilities by severity (critical > high > medium > low > info)
  const sortedVulnerabilities = [...results.vulnerabilities].sort((a, b) => {
    const severityOrder = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
    return (severityOrder[b.severity as keyof typeof severityOrder] || 0) -
           (severityOrder[a.severity as keyof typeof severityOrder] || 0);
  });

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "critical": return "text-red-600 bg-red-600/20 border-red-600/30";
      case "high": return "text-red-400 bg-red-500/20 border-red-400/30";
      case "medium": return "text-yellow-400 bg-yellow-500/20 border-yellow-400/30";
      case "low": return "text-blue-400 bg-blue-500/20 border-blue-400/30";
      case "info": return "text-gray-400 bg-gray-500/20 border-gray-400/30";
      default: return "text-gray-400 bg-gray-500/20 border-gray-400/30";
    }
  };


  const getSeverityIcon = (severity: string) => {
  switch (severity) {
    case "critical": return <XCircle className="h-5 w-5 text-red-600" />;
    case "high": return <XCircle className="h-5 w-5 text-red-400" />;
    case "medium": return <AlertTriangle className="h-5 w-5 text-yellow-400" />;
    case "low": return <AlertTriangle className="h-5 w-5 text-blue-400" />;
    case "info": return <CheckCircle className="h-5 w-5 text-gray-400" />;
    default: return <CheckCircle className="h-5 w-5 text-gray-400" />;
  }
};


  const getScoreColor = (score: number) => {
    if (score >= 80) return "text-green-400";
    if (score >= 60) return "text-yellow-400";
    return "text-red-400";
  };

  const classifySeverityFromScore = (score: number) => {
  if (score >= 9) return "critical";
  if (score >= 7) return "high";
  if (score >= 4) return "medium";
  if (score >= 1) return "low";
  return "info";
};


  return (
    <div className="max-w-4xl mx-auto">
      <div className="bg-white/10 backdrop-blur-sm rounded-2xl p-8 border border-white/20">
        {/* Header */}
        <div className="flex items-center justify-between mb-8">
          <div className="flex items-center space-x-3">
            <Shield className="h-6 w-6 text-purple-400" />
            <h3 className="text-2xl font-medium text-white">Rapport d'Analyse</h3>
          </div>
          <Button
            variant="outline"
            className="border-white/30 text-purple-400 hover:bg-white/10 hover:text-white"
            onClick={handleDownloadPDF}
          >
            <Download className="h-4 w-4 mr-2" />
            Exporter PDF
          </Button>
        </div>

        {/* Score */}
        <div className="text-center mb-8 p-6 bg-white/5 rounded-xl">
          <div className={`text-4xl font-bold mb-2 ${getScoreColor(results.score)}`}>
            {results.score}/100
          </div>
          <p className="text-slate-300">Score de Sécurité</p>
          <p className="text-sm text-slate-400 mt-2">
            Analysé le {new Date(results.timestamp).toLocaleString('fr-FR')}
          </p>
        </div>

        {/* URL */}
        <div className="mb-8 p-4 bg-slate-800/50 rounded-lg">
          <p className="text-slate-300 text-sm mb-1">URL analysée :</p>
          <p className="text-white font-mono break-all">{results.url}</p>
        </div>

        {/* Vulnerabilities */}
        <div className="space-y-4">
          <h4 className="text-xl font-medium text-white mb-4">
            Vulnérabilités Détectées ({results.vulnerabilities.length})
          </h4>
          
          {sortedVulnerabilities.map((vuln, index) => (
            <div key={index} className={`p-6 rounded-xl border ${getSeverityColor(vuln.severity)}`}>
              <div className="flex items-start space-x-4">
                <div className="flex-shrink-0 mt-1">
                  {getSeverityIcon(vuln.severity)}
                </div>
                <div className="flex-1">
                  <div className="flex items-center justify-between mb-2">
                    <h5 className="font-medium text-white">{vuln.type}</h5>
                    <span className={`px-3 py-1 rounded-full text-xs font-medium ${getSeverityColor(vuln.severity)}`}>
                      {vuln.severity.toUpperCase()}
                    </span>
                  </div>
                  <p className="text-slate-300 mb-3">{vuln.description}</p>
                  <div className="bg-black/20 p-3 rounded-lg">
                    <p className="text-sm text-slate-400 mb-1">Détails techniques :</p>
                    <p className="text-slate-300 font-mono text-sm">{vuln.details}</p>
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>

        {/* Personalized Advice */}
        {results.personalizedAdvice && results.personalizedAdvice.length > 0 && (
          <div className="mt-8 p-6 bg-blue-500/10 rounded-xl border border-blue-400/30">
            <div className="flex items-center space-x-3 mb-4">
              <CheckCircle className="h-6 w-6 text-blue-400" />
              <h4 className="text-xl font-medium text-white">Conseils Personnalisés</h4>
            </div>
            <div className="space-y-3 text-slate-300">
              {results.personalizedAdvice.map((advice, index) => (
                <div key={index} className="text-sm leading-relaxed">
                  {advice.startsWith('•') ? (
                    <div className="ml-4">{advice}</div>
                  ) : advice.startsWith('  •') ? (
                    <div className="ml-8 text-slate-400">{advice}</div>
                  ) : (
                    <div className="font-medium text-white mb-2">{advice}</div>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default ScanResults;
