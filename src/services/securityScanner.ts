import axios from 'axios';

export interface Vulnerability {
  type: string;
  severity: "low" | "medium" | "high";
  description: string;
  details: string;
  recommendation?: string;
}

export interface ScanResult {
  url: string;
  timestamp: string;
  vulnerabilities: Vulnerability[];
  score: number;
  headers: Record<string, string>;
  httpMethods: string[];
  sslInfo?: {
    valid: boolean;
    issuer?: string;
    expiryDate?: string;
  };
}

class SecurityScanner {
  private async checkHeaders(url: string): Promise<{ headers: Record<string, string>, vulnerabilities: Vulnerability[] }> {
    const vulnerabilities: Vulnerability[] = [];
    let headers: Record<string, string> = {};

    try {
      const response = await axios.head(url, {
        timeout: 10000,
        validateStatus: () => true, // Accept all status codes
      });
      
      headers = response.headers;

      // Check for missing security headers
      const securityHeaders = [
        {
          header: 'x-frame-options',
          name: 'X-Frame-Options',
          description: 'Protège contre les attaques de clickjacking',
          severity: 'medium' as const
        },
        {
          header: 'content-security-policy',
          name: 'Content-Security-Policy',
          description: 'Prévient les attaques XSS et injection de code',
          severity: 'high' as const
        },
        {
          header: 'x-content-type-options',
          name: 'X-Content-Type-Options',
          description: 'Empêche le MIME type sniffing',
          severity: 'medium' as const
        },
        {
          header: 'strict-transport-security',
          name: 'Strict-Transport-Security',
          description: 'Force l\'utilisation de HTTPS',
          severity: 'high' as const
        },
        {
          header: 'x-xss-protection',
          name: 'X-XSS-Protection',
          description: 'Active la protection XSS du navigateur',
          severity: 'low' as const
        }
      ];

      securityHeaders.forEach(({ header, name, description, severity }) => {
        if (!headers[header] && !headers[header.toLowerCase()]) {
          vulnerabilities.push({
            type: `Header de sécurité manquant: ${name}`,
            severity,
            description,
            details: `Le header ${name} n'est pas présent dans la réponse`,
            recommendation: `Ajouter le header ${name} à la configuration du serveur`
          });
        }
      });

      // Check for insecure headers
      if (headers['server']) {
        vulnerabilities.push({
          type: 'Information du serveur exposée',
          severity: 'low',
          description: 'Le header Server révèle des informations sur le serveur',
          details: `Server: ${headers['server']}`,
          recommendation: 'Masquer ou supprimer le header Server'
        });
      }

      if (headers['x-powered-by']) {
        vulnerabilities.push({
          type: 'Technologie exposée',
          severity: 'low',
          description: 'Le header X-Powered-By révèle la technologie utilisée',
          details: `X-Powered-By: ${headers['x-powered-by']}`,
          recommendation: 'Supprimer le header X-Powered-By'
        });
      }

    } catch (error) {
      if (axios.isAxiosError(error)) {
        if (error.code === 'ERR_NETWORK' || error.message.includes('CORS')) {
          vulnerabilities.push({
            type: 'Restriction CORS',
            severity: 'medium',
            description: 'Le site bloque les requêtes cross-origin (politique CORS)',
            details: 'Cette restriction est normale et indique une bonne pratique de sécurité',
            recommendation: 'Aucune action requise - c\'est une mesure de sécurité appropriée'
          });
        } else {
          vulnerabilities.push({
            type: 'Erreur de connexion',
            severity: 'high',
            description: 'Impossible de se connecter au serveur',
            details: error.message,
            recommendation: 'Vérifier que le site est accessible et que l\'URL est correcte'
          });
        }
      } else {
        vulnerabilities.push({
          type: 'Erreur de connexion',
          severity: 'high',
          description: 'Impossible de se connecter au serveur',
          details: error instanceof Error ? error.message : 'Erreur inconnue',
          recommendation: 'Vérifier que le site est accessible et que l\'URL est correcte'
        });
      }
    }

    return { headers, vulnerabilities };
  }

  private async checkHttpMethods(url: string): Promise<{ methods: string[], vulnerabilities: Vulnerability[] }> {
    const vulnerabilities: Vulnerability[] = [];
    const methods: string[] = [];
    
    try {
      const response = await axios.options(url, {
        timeout: 10000,
        validateStatus: () => true,
      });

      const allowHeader = response.headers['allow'] || response.headers['Allow'];
      if (allowHeader) {
        const allowedMethods = allowHeader.split(',').map(m => m.trim().toUpperCase());
        methods.push(...allowedMethods);

        // Check for potentially dangerous methods
        const dangerousMethods = ['PUT', 'DELETE', 'PATCH', 'TRACE'];
        const foundDangerous = allowedMethods.filter(method => dangerousMethods.includes(method));
        
        if (foundDangerous.length > 0) {
          vulnerabilities.push({
            type: 'Méthodes HTTP potentiellement dangereuses',
            severity: 'medium',
            description: 'Des méthodes HTTP sensibles sont autorisées',
            details: `Méthodes autorisées: ${foundDangerous.join(', ')}`,
            recommendation: 'Désactiver les méthodes HTTP non nécessaires'
          });
        }

        if (allowedMethods.includes('TRACE')) {
          vulnerabilities.push({
            type: 'Méthode TRACE activée',
            severity: 'medium',
            description: 'La méthode TRACE peut être utilisée pour des attaques XST',
            details: 'La méthode HTTP TRACE est autorisée',
            recommendation: 'Désactiver la méthode TRACE sur le serveur'
          });
        }
      }
    } catch (error) {
      // OPTIONS method might not be supported or blocked by CORS, this is not necessarily a vulnerability
      if (axios.isAxiosError(error) && (error.code === 'ERR_NETWORK' || error.message.includes('CORS'))) {
        // CORS blocking is actually a good security practice
        vulnerabilities.push({
          type: 'Méthodes HTTP protégées par CORS',
          severity: 'low',
          description: 'Les méthodes HTTP sont protégées par la politique CORS',
          details: 'Le serveur bloque les requêtes OPTIONS cross-origin',
          recommendation: 'Bonne pratique de sécurité - aucune action requise'
        });
      }
    }

    return { methods, vulnerabilities };
  }

  private async checkSSL(url: string): Promise<{ sslInfo?: any, vulnerabilities: Vulnerability[] }> {
    const vulnerabilities: Vulnerability[] = [];
    let sslInfo;

    try {
      if (!url.startsWith('https://')) {
        vulnerabilities.push({
          type: 'Connexion non sécurisée',
          severity: 'high',
          description: 'Le site n\'utilise pas HTTPS',
          details: 'La connexion se fait en HTTP non chiffré',
          recommendation: 'Migrer vers HTTPS avec un certificat SSL/TLS valide'
        });
      } else {
        // For HTTPS, we'll make a request and check if it succeeds
        try {
          await axios.get(url, {
            timeout: 10000,
            maxRedirects: 0,
            validateStatus: () => true,
          });
          
          sslInfo = {
            valid: true,
            issuer: 'Certificat valide',
            expiryDate: 'Non disponible via le navigateur'
          };
        } catch (error) {
          if (axios.isAxiosError(error) && error.code === 'CERT_HAS_EXPIRED') {
            vulnerabilities.push({
              type: 'Certificat SSL expiré',
              severity: 'high',
              description: 'Le certificat SSL/TLS a expiré',
              details: 'Le certificat n\'est plus valide',
              recommendation: 'Renouveler le certificat SSL/TLS'
            });
          } else if (axios.isAxiosError(error) && error.code === 'UNABLE_TO_VERIFY_LEAF_SIGNATURE') {
            vulnerabilities.push({
              type: 'Certificat SSL non valide',
              severity: 'high',
              description: 'Le certificat SSL/TLS n\'est pas valide',
              details: 'Impossible de vérifier la signature du certificat',
              recommendation: 'Installer un certificat SSL/TLS valide'
            });
          }
        }
      }
    } catch (error) {
      // SSL check failed
    }

    return { sslInfo, vulnerabilities };
  }

  private calculateScore(vulnerabilities: Vulnerability[]): number {
    let score = 100;
    
    vulnerabilities.forEach(vuln => {
      switch (vuln.severity) {
        case 'high':
          score -= 20;
          break;
        case 'medium':
          score -= 10;
          break;
        case 'low':
          score -= 5;
          break;
      }
    });

    return Math.max(0, score);
  }

  async scanWebsite(url: string): Promise<ScanResult> {
    // Normalize URL
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
      url = 'https://' + url;
    }

    const allVulnerabilities: Vulnerability[] = [];
    
    // Check headers
    const { headers, vulnerabilities: headerVulns } = await this.checkHeaders(url);
    allVulnerabilities.push(...headerVulns);

    // Check HTTP methods
    const { methods, vulnerabilities: methodVulns } = await this.checkHttpMethods(url);
    allVulnerabilities.push(...methodVulns);

    // Check SSL
    const { sslInfo, vulnerabilities: sslVulns } = await this.checkSSL(url);
    allVulnerabilities.push(...sslVulns);

    // Calculate security score
    const score = this.calculateScore(allVulnerabilities);

    return {
      url,
      timestamp: new Date().toISOString(),
      vulnerabilities: allVulnerabilities,
      score,
      headers,
      httpMethods: methods,
      sslInfo
    };
  }
}

export const securityScanner = new SecurityScanner();
