export const validateUrl = (url: string): { isValid: boolean; error?: string; normalizedUrl?: string } => {
  if (!url || url.trim() === '') {
    return { isValid: false, error: 'Veuillez saisir une URL' };
  }

  // Remove whitespace
  url = url.trim();

  // Add protocol if missing
  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    url = 'https://' + url;
  }

  try {
    const urlObj = new URL(url);
    
    // Check if it's a valid domain
    if (!urlObj.hostname || urlObj.hostname === 'localhost' || urlObj.hostname === '127.0.0.1') {
      return { 
        isValid: false, 
        error: 'Veuillez saisir une URL publique valide (localhost non autorisé)' 
      };
    }

    // Check for valid TLD (basic check)
    const parts = urlObj.hostname.split('.');
    if (parts.length < 2 || parts[parts.length - 1].length < 2) {
      return { 
        isValid: false, 
        error: 'Le nom de domaine ne semble pas valide' 
      };
    }

    return { 
      isValid: true, 
      normalizedUrl: url 
    };
  } catch (error) {
    return { 
      isValid: false, 
      error: 'Format d\'URL invalide' 
    };
  }
};

export const isValidDomain = (domain: string): boolean => {
  const domainRegex = /^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9](?:\.[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9])*$/;
  return domainRegex.test(domain);
};
