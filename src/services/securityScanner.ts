import axios from 'axios';

export interface Vulnerability {
  type: string;
  severity: "info" | "low" | "medium" | "high" | "critical";
  description: string;
  details: string;
  recommendation?: string;
  exploitable?: boolean;
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
  cookies?: CookieInfo[];
  redirects?: RedirectInfo[];
  contentInfo?: {
    hasFrames?: boolean;
    hasInlineScripts?: boolean;
    hasExternalScripts?: boolean;
    formCount?: number;
  };
  personalizedAdvice?: string[];
}

export interface CookieInfo {
  name: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite?: string;
  domain?: string;
}

export interface RedirectInfo {
  from: string;
  to: string;
  statusCode: number;
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
      
      headers = response.headers as Record<string, string>;

      // Check for missing security headers
      const securityHeaders = [
        {
          header: 'x-frame-options',
          name: 'X-Frame-Options',
          description: 'Protège contre les attaques de clickjacking',
          severity: 'medium' as const,
          exploitable: true
        },
        {
          header: 'content-security-policy',
          name: 'Content-Security-Policy',
          description: 'Prévient les attaques XSS et injection de code',
          severity: 'high' as const,
          exploitable: true
        },
        {
          header: 'x-content-type-options',
          name: 'X-Content-Type-Options',
          description: 'Empêche le MIME type sniffing',
          severity: 'medium' as const,
          exploitable: true
        },
        {
          header: 'strict-transport-security',
          name: 'Strict-Transport-Security',
          description: 'Force l\'utilisation de HTTPS',
          severity: 'high' as const,
          exploitable: true
        },
        {
          header: 'x-xss-protection',
          name: 'X-XSS-Protection',
          description: 'Active la protection XSS du navigateur',
          severity: 'info' as const,
          exploitable: false
        },
        {
          header: 'referrer-policy',
          name: 'Referrer-Policy',
          description: 'Contrôle les informations de référent envoyées',
          severity: 'low' as const,
          exploitable: false
        },
        {
          header: 'permissions-policy',
          name: 'Permissions-Policy',
          description: 'Contrôle l\'accès aux APIs du navigateur',
          severity: 'medium' as const,
          exploitable: true
        },
        {
          header: 'cross-origin-embedder-policy',
          name: 'Cross-Origin-Embedder-Policy',
          description: 'Protège contre les attaques Spectre',
          severity: 'medium' as const,
          exploitable: true
        },
        {
          header: 'cross-origin-opener-policy',
          name: 'Cross-Origin-Opener-Policy',
          description: 'Isole le contexte de navigation',
          severity: 'low' as const,
          exploitable: false
        },
        {
          header: 'cross-origin-resource-policy',
          name: 'Cross-Origin-Resource-Policy',
          description: 'Protège contre les inclusions cross-origin',
          severity: 'medium' as const,
          exploitable: true
        }
      ];

      securityHeaders.forEach(({ header, name, description, severity, exploitable }) => {
        if (!headers[header] && !headers[header.toLowerCase()]) {
          vulnerabilities.push({
            type: `Header de sécurité manquant: ${name}`,
            severity,
            description,
            details: `Le header ${name} n'est pas présent dans la réponse`,
            recommendation: `Ajouter le header ${name} à la configuration du serveur`,
            exploitable: exploitable ?? true
          });
        }
      });

      // Check for insecure headers
      if (headers['server']) {
        vulnerabilities.push({
          type: 'Information du serveur exposée',
          severity: 'info',
          description: 'Le header Server révèle des informations sur le serveur',
          details: `Server: ${headers['server']}`,
          recommendation: 'Masquer ou supprimer le header Server',
          exploitable: false
        });
      }

      if (headers['x-powered-by']) {
        vulnerabilities.push({
          type: 'Technologie exposée',
          severity: 'info',
          description: 'Le header X-Powered-By révèle la technologie utilisée',
          details: `X-Powered-By: ${headers['x-powered-by']}`,
          recommendation: 'Supprimer le header X-Powered-By',
          exploitable: false
        });
      }

      // Check CSP quality if present
      const csp = headers['content-security-policy'] || headers['Content-Security-Policy'];
      if (csp) {
        if (csp.includes('unsafe-inline')) {
          vulnerabilities.push({
            type: 'CSP avec unsafe-inline',
            severity: 'high',
            description: 'La politique CSP autorise les scripts inline',
            details: 'unsafe-inline détecté dans la CSP',
            recommendation: 'Éviter unsafe-inline et utiliser des nonces ou hashes',
            exploitable: true
          });
        }
        if (csp.includes('unsafe-eval')) {
          vulnerabilities.push({
            type: 'CSP avec unsafe-eval',
            severity: 'critical',
            description: 'La politique CSP autorise eval() et fonctions similaires',
            details: 'unsafe-eval détecté dans la CSP',
            recommendation: 'Supprimer unsafe-eval de la politique CSP',
            exploitable: true
          });
        }
        if (csp.includes('*')) {
          vulnerabilities.push({
            type: 'CSP trop permissive',
            severity: 'medium',
            description: 'La politique CSP utilise des wildcards (*)',
            details: 'Wildcard (*) détecté dans la CSP',
            recommendation: 'Spécifier des domaines précis au lieu d\'utiliser *',
            exploitable: true
          });
        }
      }

      // Check HSTS quality if present
      const hsts = headers['strict-transport-security'] || headers['Strict-Transport-Security'];
      if (hsts) {
        const maxAge = hsts.match(/max-age=(\d+)/);
        if (maxAge && parseInt(maxAge[1]) < 31536000) { // Less than 1 year
          vulnerabilities.push({
            type: 'HSTS max-age insuffisant',
            severity: 'medium',
            description: 'La durée HSTS est inférieure à 1 an',
            details: `max-age=${maxAge[1]} (recommandé: 31536000+)`,
            recommendation: 'Augmenter max-age à au moins 31536000 (1 an)',
            exploitable: true
          });
        }
        if (!hsts.includes('includeSubDomains')) {
          vulnerabilities.push({
            type: 'HSTS sans includeSubDomains',
            severity: 'info',
            description: 'HSTS ne couvre pas les sous-domaines',
            details: 'includeSubDomains manquant',
            recommendation: 'Ajouter includeSubDomains à la directive HSTS',
            exploitable: false
          });
        }
      }

      // Check for cache control issues
      const cacheControl = headers['cache-control'] || headers['Cache-Control'];
      if (!cacheControl) {
        vulnerabilities.push({
          type: 'Absence de contrôle de cache',
          severity: 'info',
          description: 'Aucune directive de cache définie',
          details: 'Header Cache-Control manquant',
          recommendation: 'Définir des directives de cache appropriées',
          exploitable: false
        });
      } else if (cacheControl.includes('no-cache') && cacheControl.includes('no-store')) {
        // This is actually good for sensitive pages
      } else if (!cacheControl.includes('private') && !cacheControl.includes('public')) {
        vulnerabilities.push({
          type: 'Contrôle de cache imprécis',
          severity: 'low',
          description: 'Les directives de cache ne spécifient pas private/public',
          details: `Cache-Control: ${cacheControl}`,
          recommendation: 'Spécifier private ou public selon le contenu'
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
        const allowedMethods = allowHeader.split(',').map((m: string) => m.trim().toUpperCase());
        methods.push(...allowedMethods);

        // Check for potentially dangerous methods
        const dangerousMethods = ['PUT', 'DELETE', 'PATCH', 'TRACE'];
        const foundDangerous = allowedMethods.filter((method: string) => dangerousMethods.includes(method));
        
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

  private async checkCookies(url: string): Promise<{ cookies: CookieInfo[], vulnerabilities: Vulnerability[] }> {
    const vulnerabilities: Vulnerability[] = [];
    const cookies: CookieInfo[] = [];

    try {
      const response = await axios.get(url, {
        timeout: 10000,
        maxRedirects: 0,
        validateStatus: () => true,
      });

      const setCookieHeaders = response.headers['set-cookie'] || [];

      if (setCookieHeaders.length === 0) {
        // No cookies is not necessarily a vulnerability
        return { cookies, vulnerabilities };
      }

      setCookieHeaders.forEach((cookieHeader: string) => {
        const cookieParts = cookieHeader.split(';').map(part => part.trim());
        const [nameValue] = cookieParts;
        const [name] = nameValue.split('=');

        const cookieInfo: CookieInfo = {
          name,
          secure: cookieParts.some(part => part.toLowerCase() === 'secure'),
          httpOnly: cookieParts.some(part => part.toLowerCase() === 'httponly'),
          sameSite: cookieParts.find(part => part.toLowerCase().startsWith('samesite='))?.split('=')[1],
          domain: cookieParts.find(part => part.toLowerCase().startsWith('domain='))?.split('=')[1]
        };

        cookies.push(cookieInfo);

        // Check for insecure cookies
        if (!cookieInfo.secure && url.startsWith('https://')) {
          vulnerabilities.push({
            type: 'Cookie non sécurisé',
            severity: 'medium',
            description: 'Cookie transmis sans l\'attribut Secure sur HTTPS',
            details: `Cookie "${name}" sans attribut Secure`,
            recommendation: 'Ajouter l\'attribut Secure aux cookies sensibles'
          });
        }

        if (!cookieInfo.httpOnly) {
          vulnerabilities.push({
            type: 'Cookie accessible en JavaScript',
            severity: 'medium',
            description: 'Cookie accessible via JavaScript (risque XSS)',
            details: `Cookie "${name}" sans attribut HttpOnly`,
            recommendation: 'Ajouter l\'attribut HttpOnly aux cookies de session'
          });
        }

        if (!cookieInfo.sameSite) {
          vulnerabilities.push({
            type: 'Cookie sans SameSite',
            severity: 'low',
            description: 'Cookie sans protection CSRF via SameSite',
            details: `Cookie "${name}" sans attribut SameSite`,
            recommendation: 'Ajouter SameSite=Strict ou SameSite=Lax'
          });
        }
      });

    } catch (error) {
      // Cookie analysis failed, not necessarily a security issue
    }

    return { cookies, vulnerabilities };
  }

  private async checkRedirects(url: string): Promise<{ redirects: RedirectInfo[], vulnerabilities: Vulnerability[] }> {
    const vulnerabilities: Vulnerability[] = [];
    const redirects: RedirectInfo[] = [];

    try {
      const response = await axios.get(url, {
        timeout: 10000,
        maxRedirects: 0,
        validateStatus: (status) => status >= 200 && status < 400,
      });

      // Check if it's a redirect
      if (response.status >= 300 && response.status < 400) {
        const location = response.headers['location'];
        if (location) {
          redirects.push({
            from: url,
            to: location,
            statusCode: response.status
          });

          // Check for insecure redirects
          if (url.startsWith('https://') && location.startsWith('http://')) {
            vulnerabilities.push({
              type: 'Redirection HTTPS vers HTTP',
              severity: 'high',
              description: 'Redirection d\'une page sécurisée vers une page non sécurisée',
              details: `${url} → ${location}`,
              recommendation: 'Rediriger uniquement vers des URLs HTTPS'
            });
          }

          // Check for open redirect vulnerability
          try {
            const locationUrl = new URL(location, url);
            const originalUrl = new URL(url);

            if (locationUrl.hostname !== originalUrl.hostname) {
              vulnerabilities.push({
                type: 'Redirection vers domaine externe',
                severity: 'medium',
                description: 'Redirection vers un domaine externe (risque d\'open redirect)',
                details: `Redirection vers ${locationUrl.hostname}`,
                recommendation: 'Valider les URLs de redirection et limiter aux domaines autorisés'
              });
            }
          } catch (error) {
            vulnerabilities.push({
              type: 'URL de redirection malformée',
              severity: 'medium',
              description: 'L\'URL de redirection n\'est pas valide',
              details: `Location: ${location}`,
              recommendation: 'Valider le format des URLs de redirection'
            });
          }
        }
      }

    } catch (error) {
      // Redirect analysis failed
      if (axios.isAxiosError(error) && error.response && error.response.status >= 300 && error.response.status < 400) {
        const location = error.response.headers['location'];
        if (location) {
          redirects.push({
            from: url,
            to: location,
            statusCode: error.response.status
          });
        }
      }
    }

    return { redirects, vulnerabilities };
  }

  private async checkContent(url: string): Promise<{ contentInfo: any, vulnerabilities: Vulnerability[] }> {
    const vulnerabilities: Vulnerability[] = [];
    const contentInfo: any = {
      hasFrames: false,
      hasInlineScripts: false,
      hasExternalScripts: false,
      formCount: 0
    };

    try {
      const response = await axios.get(url, {
        timeout: 15000,
        maxRedirects: 5,
        validateStatus: () => true,
      });

      const content = response.data;
      const contentType = response.headers['content-type'] || '';

      if (!contentType.includes('text/html')) {
        return { contentInfo, vulnerabilities };
      }

      // Check for inline scripts
      const inlineScriptRegex = /<script(?![^>]*src=)[^>]*>/gi;
      const inlineScripts = content.match(inlineScriptRegex);
      if (inlineScripts && inlineScripts.length > 0) {
        contentInfo.hasInlineScripts = true;
        vulnerabilities.push({
          type: 'Scripts inline détectés',
          severity: 'medium',
          description: 'Présence de scripts JavaScript inline',
          details: `${inlineScripts.length} script(s) inline trouvé(s)`,
          recommendation: 'Externaliser les scripts et utiliser CSP avec nonces'
        });
      }

      // Check for external scripts
      const externalScriptRegex = /<script[^>]*src=["']([^"']+)["'][^>]*>/gi;
      const externalScripts = content.match(externalScriptRegex);
      if (externalScripts && externalScripts.length > 0) {
        contentInfo.hasExternalScripts = true;

        // Check for scripts from external domains
        externalScripts.forEach((script: string) => {
          const srcMatch = script.match(/src=["']([^"']+)["']/);
          if (srcMatch) {
            const scriptSrc = srcMatch[1];
            try {
              const scriptUrl = new URL(scriptSrc, url);
              const pageUrl = new URL(url);

              if (scriptUrl.hostname !== pageUrl.hostname) {
                vulnerabilities.push({
                  type: 'Script externe non sécurisé',
                  severity: 'medium',
                  description: 'Chargement de scripts depuis des domaines externes',
                  details: `Script depuis ${scriptUrl.hostname}`,
                  recommendation: 'Vérifier l\'intégrité des scripts externes avec SRI'
                });
              }
            } catch (error) {
              // Invalid URL in script src
            }
          }
        });
      }

      // Check for iframes
      const iframeRegex = /<iframe[^>]*>/gi;
      const iframes = content.match(iframeRegex);
      if (iframes && iframes.length > 0) {
        contentInfo.hasFrames = true;
        vulnerabilities.push({
          type: 'iFrames détectées',
          severity: 'low',
          description: 'Présence d\'iframes dans la page',
          details: `${iframes.length} iframe(s) trouvée(s)`,
          recommendation: 'Vérifier la sécurité des contenus embarqués et utiliser sandbox'
        });
      }

      // Check for forms
      const formRegex = /<form[^>]*>/gi;
      const forms = content.match(formRegex);
      if (forms && forms.length > 0) {
        contentInfo.formCount = forms.length;

        // Check for forms without CSRF protection indicators
        const csrfTokenRegex = /(csrf|_token|authenticity_token)/gi;
        const hasCSRFTokens = content.match(csrfTokenRegex);

        if (!hasCSRFTokens) {
          vulnerabilities.push({
            type: 'Formulaires sans protection CSRF',
            severity: 'medium',
            description: 'Aucun token CSRF détecté dans les formulaires',
            details: `${forms.length} formulaire(s) sans protection CSRF apparente`,
            recommendation: 'Implémenter des tokens CSRF pour tous les formulaires'
          });
        }

        // Check for forms over HTTP
        if (url.startsWith('http://')) {
          vulnerabilities.push({
            type: 'Formulaires non sécurisés',
            severity: 'high',
            description: 'Formulaires transmis en HTTP non chiffré',
            details: 'Données de formulaire exposées en transit',
            recommendation: 'Migrer vers HTTPS pour protéger les données sensibles'
          });
        }
      }

      // Check for mixed content
      if (url.startsWith('https://')) {
        const httpResourceRegex = /(src|href|action)=["']http:\/\/[^"']+["']/gi;
        const httpResources = content.match(httpResourceRegex);
        if (httpResources && httpResources.length > 0) {
          vulnerabilities.push({
            type: 'Contenu mixte (Mixed Content)',
            severity: 'medium',
            description: 'Ressources HTTP chargées depuis une page HTTPS',
            details: `${httpResources.length} ressource(s) HTTP détectée(s)`,
            recommendation: 'Migrer toutes les ressources vers HTTPS'
          });
        }
      }

    } catch (error) {
      // Content analysis failed
      if (axios.isAxiosError(error) && error.code !== 'ERR_NETWORK') {
        vulnerabilities.push({
          type: 'Erreur d\'analyse du contenu',
          severity: 'low',
          description: 'Impossible d\'analyser le contenu de la page',
          details: error.message,
          recommendation: 'Vérifier l\'accessibilité de la page'
        });
      }
    }

    return { contentInfo, vulnerabilities };
  }

  private async checkSSL(url: string): Promise<{ sslInfo?: any, vulnerabilities: Vulnerability[] }> {
    const vulnerabilities: Vulnerability[] = [];
    let sslInfo: any;

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
      if (vuln.severity === 'critical') score -= 20;
      else if (vuln.severity === 'high') score -= 15;
      else if (vuln.severity === 'medium') score -= 10;
      else if (vuln.severity === 'low') score -= 5;
      // Exclude 'info' from scoring as they are non-exploitable.
    });
    return Math.max(0, Math.min(100, score));
  }

  private generatePersonalizedAdvice(vulnerabilities: Vulnerability[]): string[] {
    const advice: string[] = [];
    const vulnTypes = vulnerabilities.map(v => v.type);
    const severities = vulnerabilities.map(v => v.severity);

    // Analyse des vulnérabilités critiques et high
    const criticalVulns = vulnerabilities.filter(v => v.severity === 'critical');
    const highVulns = vulnerabilities.filter(v => v.severity === 'high');

    if (criticalVulns.length > 0) {
      advice.push("🚨 PRIORITÉ ABSOLUE : Vous avez des vulnérabilités critiques qui nécessitent une correction immédiate. Ces failles peuvent être exploitées facilement par des attaquants.");

      if (criticalVulns.some(v => v.type.includes('CSP'))) {
        advice.push("• Votre Content Security Policy (CSP) présente des failles critiques. Révisez immédiatement votre politique CSP pour éliminer 'unsafe-eval' et renforcer les restrictions.");
      }
    }

    if (highVulns.length > 0) {
      advice.push("⚠️ HAUTE PRIORITÉ : Plusieurs vulnérabilités de haute sévérité ont été détectées. Planifiez leur correction dans les plus brefs délais.");

      if (highVulns.some(v => v.type.includes('HTTPS') || v.type.includes('SSL') || v.type.includes('TLS'))) {
        advice.push("• Problèmes de chiffrement détectés : Assurez-vous d'utiliser HTTPS avec des certificats valides et des versions TLS récentes (1.2+).");
      }

      if (highVulns.some(v => v.type.includes('Content-Security-Policy'))) {
        advice.push("• CSP manquante : Implémentez une Content Security Policy robuste pour prévenir les attaques XSS et d'injection de code.");
      }

      if (highVulns.some(v => v.type.includes('Strict-Transport-Security'))) {
        advice.push("• HSTS manquant : Activez HTTP Strict Transport Security pour forcer l'utilisation de HTTPS.");
      }
    }

    // Conseils basés sur les types de vulnérabilités
    if (vulnTypes.some(type => type.includes('Header de sécurité manquant'))) {
      const missingHeaders = vulnerabilities.filter(v => v.type.includes('Header de sécurité manquant')).length;
      advice.push(`📋 Configuration des headers : ${missingHeaders} header(s) de sécurité manquant(s). Configurez votre serveur web pour inclure tous les headers de sécurité recommandés.`);
    }

    if (vulnTypes.some(type => type.includes('Cookie'))) {
      advice.push("🍪 Sécurité des cookies : Configurez vos cookies avec les attributs Secure, HttpOnly et SameSite appropriés pour prévenir les attaques de session.");
    }

    if (vulnTypes.some(type => type.includes('CSRF'))) {
      advice.push("🛡️ Protection CSRF : Implémentez des tokens CSRF pour tous vos formulaires afin de prévenir les attaques Cross-Site Request Forgery.");
    }

    if (vulnTypes.some(type => type.includes('Information') || type.includes('Technologie'))) {
      advice.push("🔒 Divulgation d'informations : Masquez les informations sur votre serveur et les technologies utilisées pour réduire la surface d'attaque.");
    }

    if (vulnTypes.some(type => type.includes('méthode HTTP'))) {
      advice.push("🌐 Méthodes HTTP : Désactivez les méthodes HTTP non nécessaires (PUT, DELETE, TRACE) pour réduire les risques d'exploitation.");
    }

    // Conseils basés sur le score global
    const score = this.calculateScore(vulnerabilities);
    if (score < 50) {
      advice.push("🔴 Score critique : Votre site présente de nombreuses vulnérabilités. Considérez un audit de sécurité complet et implémentez un plan de remédiation urgent.");
    } else if (score < 70) {
      advice.push("🟡 Améliorations nécessaires : Votre sécurité peut être significativement améliorée. Priorisez la correction des vulnérabilités de haute et moyenne sévérité.");
    } else if (score < 85) {
      advice.push("🟢 Bonne base de sécurité : Votre site a une sécurité correcte, mais quelques améliorations peuvent encore renforcer votre posture de sécurité.");
    }

    // Conseils généraux basés sur les vulnérabilités détectées
    if (vulnerabilities.length > 0) {
      advice.push("📚 Recommandations générales :");
      advice.push("  • Effectuez des tests de sécurité réguliers avec cet outil");
      advice.push("  • Tenez vos systèmes et dépendances à jour");
      advice.push("  • Formez votre équipe aux bonnes pratiques de sécurité");
      advice.push("  • Considérez l'implémentation d'un WAF (Web Application Firewall)");
      advice.push("  • Mettez en place une surveillance de sécurité continue");
    }

    return advice;
  }

  private async performAdvancedChecks(url: string, headers: Record<string, string>): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];

    // Check for information disclosure in headers
    const sensitiveHeaders = [
      'x-aspnet-version', 'x-aspnetmvc-version', 'x-powered-by',
      'server', 'x-generator', 'x-drupal-cache', 'x-varnish'
    ];

    sensitiveHeaders.forEach(header => {
      if (headers[header] || headers[header.toLowerCase()]) {
        vulnerabilities.push({
          type: 'Divulgation d\'informations techniques',
          severity: 'low',
          description: `Header ${header} révèle des informations sur la stack technique`,
          details: `${header}: ${headers[header] || headers[header.toLowerCase()]}`,
          recommendation: 'Supprimer ou masquer les headers révélant des informations techniques'
        });
      }
    });

    // Check for weak cipher suites (simulated check)
    if (url.startsWith('https://')) {
      try {
        const response = await axios.get(url, {
          timeout: 5000,
          maxRedirects: 0,
          validateStatus: () => true,
        });

        // Check for deprecated TLS versions indicators
        const serverHeader = response.headers['server'] || '';
        if (serverHeader.includes('TLS/1.0') || serverHeader.includes('TLS/1.1')) {
          vulnerabilities.push({
            type: 'Version TLS obsolète',
            severity: 'high',
            description: 'Le serveur supporte des versions TLS obsolètes',
            details: 'TLS 1.0 ou 1.1 détecté',
            recommendation: 'Désactiver TLS 1.0 et 1.1, utiliser uniquement TLS 1.2+'
          });
        }
      } catch (error) {
        // TLS check failed
      }
    }

    // Check for common security misconfigurations
    await this.checkSecurityMisconfigurations(url, vulnerabilities);

    // Check for potential subdomain takeover
    await this.checkSubdomainSecurity(url, vulnerabilities);

    // Check for email disclosure
    await this.checkEmailDisclosure(url, vulnerabilities);

    return vulnerabilities;
  }

  private async checkSecurityMisconfigurations(url: string, vulnerabilities: Vulnerability[]): Promise<void> {
    const commonPaths = [
      '/.env', '/config.php', '/wp-config.php', '/admin', '/administrator',
      '/phpmyadmin', '/backup', '/.git', '/robots.txt', '/sitemap.xml'
    ];

    const baseUrl = new URL(url).origin;

    for (const path of commonPaths) {
      try {
        const response = await axios.head(`${baseUrl}${path}`, {
          timeout: 3000,
          validateStatus: () => true,
        });

        if (response.status === 200) {
          let severity: 'low' | 'medium' | 'high' = 'low';
          let description = 'Fichier ou répertoire sensible accessible';

          if (path.includes('.env') || path.includes('config')) {
            severity = 'high';
            description = 'Fichier de configuration sensible exposé';
          } else if (path.includes('admin') || path.includes('phpmyadmin')) {
            severity = 'medium';
            description = 'Interface d\'administration accessible';
          } else if (path.includes('.git') || path.includes('backup')) {
            severity = 'high';
            description = 'Données sensibles potentiellement exposées';
          }

          vulnerabilities.push({
            type: 'Exposition de fichiers sensibles',
            severity,
            description,
            details: `${path} accessible (HTTP ${response.status})`,
            recommendation: 'Restreindre l\'accès aux fichiers et répertoires sensibles'
          });
        }
      } catch (error) {
        // Path check failed, continue
      }
    }
  }

  private async checkSubdomainSecurity(url: string, vulnerabilities: Vulnerability[]): Promise<void> {
    try {
      const urlObj = new URL(url);
      const domain = urlObj.hostname;

      // Check for wildcard subdomains (basic check)
      const commonSubdomains = ['www', 'mail', 'ftp', 'admin', 'test', 'dev', 'staging'];

      for (const subdomain of commonSubdomains) {
        try {
          const subdomainUrl = `https://${subdomain}.${domain}`;
          const response = await axios.head(subdomainUrl, {
            timeout: 2000,
            validateStatus: () => true,
          });

          if (response.status === 200) {
            // Check if subdomain has weaker security
            const subHeaders = response.headers;
            const hasHSTS = subHeaders['strict-transport-security'];
            const hasCSP = subHeaders['content-security-policy'];

            if (!hasHSTS || !hasCSP) {
              vulnerabilities.push({
                type: 'Sous-domaine avec sécurité faible',
                severity: 'medium',
                description: 'Sous-domaine détecté avec des mesures de sécurité insuffisantes',
                details: `${subdomainUrl} manque de headers de sécurité`,
                recommendation: 'Appliquer les mêmes mesures de sécurité à tous les sous-domaines'
              });
            }
          }
        } catch (error) {
          // Subdomain check failed
        }
      }
    } catch (error) {
      // Subdomain security check failed
    }
  }

  private async checkEmailDisclosure(url: string, vulnerabilities: Vulnerability[]): Promise<void> {
    try {
      const response = await axios.get(url, {
        timeout: 10000,
        maxRedirects: 5,
        validateStatus: () => true,
      });

      const content = response.data;
      const emailRegex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
      const emails = content.match(emailRegex);

      if (emails && emails.length > 0) {
        const uniqueEmails = [...new Set(emails)];
        vulnerabilities.push({
          type: 'Divulgation d\'adresses email',
          severity: 'low',
          description: 'Adresses email exposées dans le code source',
          details: `${uniqueEmails.length} adresse(s) email trouvée(s)`,
          recommendation: 'Masquer les adresses email ou utiliser des formulaires de contact'
        });
      }
    } catch (error) {
      // Email disclosure check failed
    }
  }

  private async checkWebApplicationSecurity(url: string): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];

    try {
      // Check for SQL injection indicators in error pages
      const sqlTestPaths = [
        "/?id=1'", "/?search=test'", "/?page=1'"
      ];

      for (const testPath of sqlTestPaths) {
        try {
          const response = await axios.get(`${url}${testPath}`, {
            timeout: 5000,
            validateStatus: () => true,
          });

          const content = response.data.toLowerCase();
          const sqlErrorPatterns = [
            'sql syntax', 'mysql_fetch', 'ora-', 'microsoft ole db',
            'unclosed quotation mark', 'quoted string not properly terminated'
          ];

          const foundErrors = sqlErrorPatterns.filter(pattern => content.includes(pattern));
          if (foundErrors.length > 0) {
            vulnerabilities.push({
              type: 'Potentielle vulnérabilité SQL Injection',
              severity: 'high',
              description: 'Messages d\'erreur SQL détectés dans les réponses',
              details: `Erreurs détectées: ${foundErrors.join(', ')}`,
              recommendation: 'Implémenter une gestion d\'erreur sécurisée et utiliser des requêtes préparées'
            });
            break; // Don't spam with multiple similar vulnerabilities
          }
        } catch (error) {
          // Test failed, continue
        }
      }

      // Check for directory traversal vulnerability
      const traversalPaths = [
        '/../../../etc/passwd', '/..\\..\\..\\windows\\system32\\drivers\\etc\\hosts'
      ];

      for (const traversalPath of traversalPaths) {
        try {
          const response = await axios.get(`${url}${traversalPath}`, {
            timeout: 5000,
            validateStatus: () => true,
          });

          if (response.status === 200 &&
              (response.data.includes('root:') || response.data.includes('localhost'))) {
            vulnerabilities.push({
              type: 'Vulnérabilité Directory Traversal',
              severity: 'high',
              description: 'Possible accès aux fichiers système via directory traversal',
              details: `Chemin testé: ${traversalPath}`,
              recommendation: 'Valider et filtrer tous les paramètres de chemin d\'accès'
            });
            break;
          }
        } catch (error) {
          // Test failed, continue
        }
      }

      // Check for XSS vulnerability indicators
      const xssTestPayloads = [
        '?search=<script>alert(1)</script>',
        '?q="><img src=x onerror=alert(1)>'
      ];

      for (const payload of xssTestPayloads) {
        try {
          const response = await axios.get(`${url}${payload}`, {
            timeout: 5000,
            validateStatus: () => true,
          });

          const content = response.data;
          if (content.includes('<script>alert(1)</script>') ||
              content.includes('<img src=x onerror=alert(1)>')) {
            vulnerabilities.push({
              type: 'Potentielle vulnérabilité XSS',
              severity: 'high',
              description: 'Injection de code JavaScript possible',
              details: 'Payload XSS reflété dans la réponse',
              recommendation: 'Encoder toutes les entrées utilisateur et implémenter CSP strict'
            });
            break;
          }
        } catch (error) {
          // Test failed, continue
        }
      }

      // Check for clickjacking protection
      const response = await axios.get(url, {
        timeout: 10000,
        validateStatus: () => true,
      });

      const xFrameOptions = response.headers['x-frame-options'];
      const csp = response.headers['content-security-policy'];

      if (!xFrameOptions && (!csp || !csp.includes('frame-ancestors'))) {
        vulnerabilities.push({
          type: 'Absence de protection Clickjacking',
          severity: 'medium',
          description: 'La page peut être intégrée dans une iframe malveillante',
          details: 'Ni X-Frame-Options ni CSP frame-ancestors défini',
          recommendation: 'Ajouter X-Frame-Options: DENY ou CSP frame-ancestors \'none\''
        });
      }

    } catch (error) {
      // Web application security check failed
    }

    return vulnerabilities;
  }

  private async checkAPIEndpoints(url: string): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];

    try {
      const baseUrl = new URL(url).origin;
      const commonAPIEndpoints = [
        '/api', '/api/v1', '/api/v2', '/rest', '/graphql',
        '/swagger', '/api-docs', '/openapi.json'
      ];

      for (const endpoint of commonAPIEndpoints) {
        try {
          const response = await axios.get(`${baseUrl}${endpoint}`, {
            timeout: 5000,
            validateStatus: () => true,
          });

          if (response.status === 200) {
            const contentType = response.headers['content-type'] || '';

            // Check for API documentation exposure
            if (endpoint.includes('swagger') || endpoint.includes('api-docs') ||
                endpoint.includes('openapi')) {
              vulnerabilities.push({
                type: 'Documentation API exposée',
                severity: 'medium',
                description: 'Documentation API accessible publiquement',
                details: `${endpoint} accessible (${response.status})`,
                recommendation: 'Restreindre l\'accès à la documentation API en production'
              });
            }

            // Check for missing API authentication
            if (contentType.includes('application/json') && response.status === 200) {
              try {
                const data = JSON.parse(response.data);
                if (data && typeof data === 'object') {
                  vulnerabilities.push({
                    type: 'API sans authentification',
                    severity: 'medium',
                    description: 'Endpoint API accessible sans authentification',
                    details: `${endpoint} retourne des données JSON`,
                    recommendation: 'Implémenter une authentification appropriée pour les APIs'
                  });
                }
              } catch (error) {
                // Not valid JSON
              }
            }

            // Check for CORS misconfigurations
            const corsOrigin = response.headers['access-control-allow-origin'];
            if (corsOrigin === '*') {
              vulnerabilities.push({
                type: 'Configuration CORS permissive',
                severity: 'medium',
                description: 'CORS configuré pour accepter toutes les origines',
                details: 'Access-Control-Allow-Origin: *',
                recommendation: 'Restreindre CORS aux domaines autorisés uniquement'
              });
            }
          }
        } catch (error) {
          // API endpoint check failed
        }
      }

      // Check for GraphQL introspection
      try {
        const graphqlResponse = await axios.post(`${baseUrl}/graphql`, {
          query: '{ __schema { types { name } } }'
        }, {
          timeout: 5000,
          validateStatus: () => true,
        });

        if (graphqlResponse.status === 200 && graphqlResponse.data.data) {
          vulnerabilities.push({
            type: 'GraphQL Introspection activée',
            severity: 'medium',
            description: 'L\'introspection GraphQL est activée en production',
            details: 'Schema GraphQL accessible via introspection',
            recommendation: 'Désactiver l\'introspection GraphQL en production'
          });
        }
      } catch (error) {
        // GraphQL check failed
      }

    } catch (error) {
      // API security check failed
    }

    return vulnerabilities;
  }

  private async checkModernWebSecurity(url: string, headers: Record<string, string>): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];

    try {
      // Check for Service Worker security
      const response = await axios.get(url, {
        timeout: 10000,
        validateStatus: () => true,
      });

      const content = response.data;

      // Check for Service Worker registration
      if (content.includes('serviceWorker.register') || content.includes('navigator.serviceWorker')) {
        // Check if HTTPS is used (required for Service Workers)
        if (!url.startsWith('https://')) {
          vulnerabilities.push({
            type: 'Service Worker sur HTTP',
            severity: 'high',
            description: 'Service Worker détecté sur une connexion non sécurisée',
            details: 'Les Service Workers nécessitent HTTPS',
            recommendation: 'Migrer vers HTTPS pour utiliser les Service Workers en sécurité'
          });
        }

        // Check for CSP compatibility with Service Workers
        const csp = headers['content-security-policy'];
        if (csp && !csp.includes('worker-src') && !csp.includes('script-src')) {
          vulnerabilities.push({
            type: 'CSP incompatible avec Service Worker',
            severity: 'medium',
            description: 'CSP ne définit pas de politique pour les Service Workers',
            details: 'worker-src ou script-src manquant dans CSP',
            recommendation: 'Ajouter worker-src à la politique CSP'
          });
        }
      }

      // Check for WebAssembly usage
      if (content.includes('WebAssembly') || content.includes('.wasm')) {
        const csp = headers['content-security-policy'];
        if (csp && !csp.includes('unsafe-eval') && !csp.includes('wasm-unsafe-eval')) {
          // This is actually good - WebAssembly without unsafe-eval
        } else if (csp && csp.includes('unsafe-eval')) {
          vulnerabilities.push({
            type: 'WebAssembly avec unsafe-eval',
            severity: 'medium',
            description: 'WebAssembly utilisé avec CSP unsafe-eval',
            details: 'unsafe-eval peut permettre l\'exécution de code arbitraire',
            recommendation: 'Utiliser wasm-unsafe-eval au lieu de unsafe-eval pour WebAssembly'
          });
        }
      }

      // Check for Web Workers security
      if (content.includes('new Worker(') || content.includes('new SharedWorker(')) {
        const csp = headers['content-security-policy'];
        if (csp && !csp.includes('worker-src')) {
          vulnerabilities.push({
            type: 'Web Workers sans politique CSP',
            severity: 'medium',
            description: 'Web Workers utilisés sans directive worker-src dans CSP',
            details: 'worker-src manquant dans la politique CSP',
            recommendation: 'Ajouter worker-src à la politique de sécurité du contenu'
          });
        }
      }

      // Check for Trusted Types support
      const trustedTypes = headers['require-trusted-types-for'];
      if (!trustedTypes && content.includes('innerHTML')) {
        vulnerabilities.push({
          type: 'Absence de Trusted Types',
          severity: 'medium',
          description: 'innerHTML utilisé sans protection Trusted Types',
          details: 'Require-Trusted-Types-For header manquant',
          recommendation: 'Implémenter Trusted Types pour prévenir les injections DOM'
        });
      }

      // Check for Subresource Integrity (SRI)
      const scriptTags = content.match(/<script[^>]*src=["'][^"']*["'][^>]*>/gi) || [];
      const linkTags = content.match(/<link[^>]*href=["'][^"']*["'][^>]*>/gi) || [];

      let externalResourcesWithoutSRI = 0;

      [...scriptTags, ...linkTags].forEach(tag => {
        const isExternal = tag.includes('http://') || tag.includes('https://');
        const hasSRI = tag.includes('integrity=');

        if (isExternal && !hasSRI) {
          externalResourcesWithoutSRI++;
        }
      });

      if (externalResourcesWithoutSRI > 0) {
        vulnerabilities.push({
          type: 'Ressources externes sans SRI',
          severity: 'medium',
          description: 'Ressources externes chargées sans vérification d\'intégrité',
          details: `${externalResourcesWithoutSRI} ressource(s) externe(s) sans attribut integrity`,
          recommendation: 'Ajouter des attributs integrity (SRI) aux ressources externes'
        });
      }

      // Check for Feature Policy / Permissions Policy
      const featurePolicy = headers['feature-policy'] || headers['permissions-policy'];
      if (!featurePolicy) {
        vulnerabilities.push({
          type: 'Absence de Permissions Policy',
          severity: 'low',
          description: 'Aucune politique de permissions définie',
          details: 'Feature-Policy ou Permissions-Policy header manquant',
          recommendation: 'Définir une Permissions Policy pour contrôler l\'accès aux APIs'
        });
      }

      // Check for Cross-Origin policies
      const coep = headers['cross-origin-embedder-policy'];
      const coop = headers['cross-origin-opener-policy'];
      const corp = headers['cross-origin-resource-policy'];

      if (!coep && !coop && !corp) {
        vulnerabilities.push({
          type: 'Politiques Cross-Origin manquantes',
          severity: 'medium',
          description: 'Aucune politique cross-origin définie',
          details: 'COEP, COOP et CORP headers manquants',
          recommendation: 'Implémenter les politiques cross-origin appropriées'
        });
      }

      // Check for modern authentication patterns
      if (content.includes('localStorage.setItem') && content.includes('token')) {
        vulnerabilities.push({
          type: 'Stockage de tokens en localStorage',
          severity: 'medium',
          description: 'Tokens potentiellement stockés en localStorage',
          details: 'localStorage utilisé pour stocker des tokens',
          recommendation: 'Utiliser httpOnly cookies ou sessionStorage pour les tokens sensibles'
        });
      }

    } catch (error) {
      // Modern web security check failed
    }

    return vulnerabilities;
  }

  async scanWebsite(url: string): Promise<ScanResult> {
    // Normalize URL
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
      url = 'https://' + url;
    }

    const allVulnerabilities: Vulnerability[] = [];

    // Run all security checks in parallel for better performance
    const results = await Promise.allSettled([
      this.checkHeaders(url),
      this.checkHttpMethods(url),
      this.checkSSL(url),
      this.checkCookies(url),
      this.checkRedirects(url),
      this.checkContent(url)
    ]);

    // Extract results safely
    const headerResult = results[0].status === 'fulfilled' ? results[0].value : { headers: {}, vulnerabilities: [] };
    const methodResult = results[1].status === 'fulfilled' ? results[1].value : { methods: [], vulnerabilities: [] };
    const sslResult = results[2].status === 'fulfilled' ? results[2].value : { sslInfo: undefined, vulnerabilities: [] };
    const cookieResult = results[3].status === 'fulfilled' ? results[3].value : { cookies: [], vulnerabilities: [] };
    const redirectResult = results[4].status === 'fulfilled' ? results[4].value : { redirects: [], vulnerabilities: [] };
    const contentResult = results[5].status === 'fulfilled' ? results[5].value : { contentInfo: {}, vulnerabilities: [] };

    const { headers, vulnerabilities: headerVulns } = headerResult;
    const { methods, vulnerabilities: methodVulns } = methodResult;
    const { sslInfo, vulnerabilities: sslVulns } = sslResult;
    const { cookies, vulnerabilities: cookieVulns } = cookieResult;
    const { redirects, vulnerabilities: redirectVulns } = redirectResult;
    const { contentInfo, vulnerabilities: contentVulns } = contentResult;

    // Combine all vulnerabilities
    allVulnerabilities.push(...headerVulns);
    allVulnerabilities.push(...methodVulns);
    allVulnerabilities.push(...sslVulns);
    allVulnerabilities.push(...cookieVulns);
    allVulnerabilities.push(...redirectVulns);
    allVulnerabilities.push(...contentVulns);

    // Additional advanced checks
    const advancedVulns = await this.performAdvancedChecks(url, headers);
    allVulnerabilities.push(...advancedVulns);

    // Web application security checks
    const webAppVulns = await this.checkWebApplicationSecurity(url);
    allVulnerabilities.push(...webAppVulns);

    // API security checks
    const apiVulns = await this.checkAPIEndpoints(url);
    allVulnerabilities.push(...apiVulns);

    // Modern web security checks
    const modernWebVulns = await this.checkModernWebSecurity(url, headers);
    allVulnerabilities.push(...modernWebVulns);

    // Calculate security score
    const score = this.calculateScore(allVulnerabilities);

    // Generate personalized advice
    const personalizedAdvice = this.generatePersonalizedAdvice(allVulnerabilities);

    return {
      url,
      timestamp: new Date().toISOString(),
      vulnerabilities: allVulnerabilities,
      score,
      headers: headers || {},
      httpMethods: methods || [],
      sslInfo,
      cookies,
      redirects,
      contentInfo,
      personalizedAdvice
    };
  }
}

export const securityScanner = new SecurityScanner();
