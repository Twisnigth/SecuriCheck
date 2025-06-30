import jsPDF from 'jspdf';
import { ScanResult, Vulnerability } from './securityScanner';

class PDFGenerator {
  private addHeader(doc: jsPDF, title: string) {
    // Add logo/title area
    doc.setFillColor(88, 28, 135); // Purple color
    doc.rect(0, 0, 210, 30, 'F');
    
    // Title
    doc.setTextColor(255, 255, 255);
    doc.setFontSize(20);
    doc.setFont('helvetica', 'bold');
    doc.text('Cyber Sensei - Rapport de Sécurité', 20, 20);
    
    // Reset color
    doc.setTextColor(0, 0, 0);
  }

  private addFooter(doc: jsPDF, pageNumber: number) {
    const pageHeight = doc.internal.pageSize.height;
    doc.setFontSize(8);
    doc.setTextColor(128, 128, 128);
    doc.text(`Page ${pageNumber} - Généré le ${new Date().toLocaleDateString('fr-FR')}`, 20, pageHeight - 10);
    doc.text('Securicheck', 150, pageHeight - 10);
  }

  private getSeverityColor(severity: string): [number, number, number] {
    switch (severity) {
      case 'high': return [239, 68, 68]; // Red
      case 'medium': return [245, 158, 11]; // Orange
      case 'low': return [59, 130, 246]; // Blue
      default: return [107, 114, 128]; // Gray
    }
  }

  private addSummarySection(doc: jsPDF, result: ScanResult, startY: number): number {
    let currentY = startY;
    
    // Section title
    doc.setFontSize(16);
    doc.setFont('helvetica', 'bold');
    doc.text('Résumé de l\'analyse', 20, currentY);
    currentY += 15;

    // URL analyzed
    doc.setFontSize(12);
    doc.setFont('helvetica', 'normal');
    doc.text('URL analysée:', 20, currentY);
    doc.setFont('helvetica', 'bold');
    doc.text(result.url, 20, currentY + 7);
    currentY += 20;

    // Date
    doc.setFont('helvetica', 'normal');
    doc.text('Date d\'analyse:', 20, currentY);
    doc.setFont('helvetica', 'bold');
    doc.text(new Date(result.timestamp).toLocaleString('fr-FR'), 20, currentY + 7);
    currentY += 20;

    // Security Score
    doc.setFont('helvetica', 'normal');
    doc.text('Score de sécurité:', 20, currentY);
    
    // Score with color
    const scoreColor = result.score >= 80 ? [34, 197, 94] : result.score >= 60 ? [245, 158, 11] : [239, 68, 68];
    doc.setTextColor(scoreColor[0], scoreColor[1], scoreColor[2]);
    doc.setFontSize(24);
    doc.setFont('helvetica', 'bold');
    doc.text(`${result.score}/100`, 20, currentY + 15);
    
    // Reset color
    doc.setTextColor(0, 0, 0);
    doc.setFontSize(12);
    currentY += 25;

    // Vulnerability count
    doc.setFont('helvetica', 'normal');
    doc.text(`Nombre de vulnérabilités détectées: ${result.vulnerabilities.length}`, 20, currentY);
    currentY += 15;

    return currentY;
  }

  private addVulnerabilitiesSection(doc: jsPDF, vulnerabilities: Vulnerability[], startY: number): number {
    let currentY = startY;
    
    // Section title
    doc.setFontSize(16);
    doc.setFont('helvetica', 'bold');
    doc.text('Vulnérabilités détectées', 20, currentY);
    currentY += 15;

    if (vulnerabilities.length === 0) {
      doc.setFontSize(12);
      doc.setFont('helvetica', 'normal');
      doc.setTextColor(34, 197, 94);
      doc.text('Aucune vulnérabilité détectée !', 20, currentY);
      doc.setTextColor(0, 0, 0);
      currentY += 15;
      return currentY;
    }

    vulnerabilities.forEach((vuln, index) => {
      // Check if we need a new page
      if (currentY > 250) {
        doc.addPage();
        this.addHeader(doc, 'Rapport de Sécurité');
        currentY = 50;
      }

      // Vulnerability number and type
      doc.setFontSize(14);
      doc.setFont('helvetica', 'bold');
      doc.text(`${index + 1}. ${vuln.type}`, 20, currentY);
      currentY += 10;

      // Severity badge
      const severityColor = this.getSeverityColor(vuln.severity);
      doc.setFillColor(...severityColor);
      doc.roundedRect(20, currentY - 5, 25, 8, 2, 2, 'F');
      doc.setTextColor(255, 255, 255);
      doc.setFontSize(10);
      doc.setFont('helvetica', 'bold');
      doc.text(vuln.severity.toUpperCase(), 22, currentY);
      doc.setTextColor(0, 0, 0);
      currentY += 15;

      // Description
      doc.setFontSize(11);
      doc.setFont('helvetica', 'normal');
      const descriptionLines = doc.splitTextToSize(vuln.description, 170);
      doc.text(descriptionLines, 20, currentY);
      currentY += descriptionLines.length * 5 + 5;

      // Details
      if (vuln.details) {
        doc.setFont('helvetica', 'bold');
        doc.text('Détails techniques:', 20, currentY);
        currentY += 7;
        doc.setFont('helvetica', 'normal');
        doc.setFontSize(10);
        const detailsLines = doc.splitTextToSize(vuln.details, 170);
        doc.text(detailsLines, 25, currentY);
        currentY += detailsLines.length * 4 + 5;
      }

      // Recommendation
      if (vuln.recommendation) {
        doc.setFontSize(11);
        doc.setFont('helvetica', 'bold');
        doc.text('Recommandation:', 20, currentY);
        currentY += 7;
        doc.setFont('helvetica', 'normal');
        const recLines = doc.splitTextToSize(vuln.recommendation, 170);
        doc.text(recLines, 25, currentY);
        currentY += recLines.length * 5 + 10;
      }

      currentY += 5; // Space between vulnerabilities
    });

    return currentY;
  }

  private addRecommendationsSection(doc: jsPDF, startY: number): number {
    let currentY = startY;
    
    // Check if we need a new page
    if (currentY > 220) {
      doc.addPage();
      this.addHeader(doc, 'Rapport de Sécurité');
      currentY = 50;
    }

    // Section title
    doc.setFontSize(16);
    doc.setFont('helvetica', 'bold');
    doc.text('Recommandations générales', 20, currentY);
    currentY += 15;

    const recommendations = [
      'Configurez tous les headers de sécurité recommandés (CSP, X-Frame-Options, etc.)',
      'Utilisez toujours HTTPS avec des certificats SSL/TLS valides',
      'Désactivez les méthodes HTTP non nécessaires',
      'Masquez les informations sur le serveur et les technologies utilisées',
      'Effectuez des audits de sécurité réguliers',
      'Tenez vos systèmes et dépendances à jour',
      'Implémentez une politique de sécurité stricte',
      'Formez votre équipe aux bonnes pratiques de sécurité'
    ];

    doc.setFontSize(11);
    doc.setFont('helvetica', 'normal');

    recommendations.forEach((rec, index) => {
      if (currentY > 270) {
        doc.addPage();
        this.addHeader(doc, 'Rapport de Sécurité');
        currentY = 50;
      }
      
      doc.text(`• ${rec}`, 25, currentY);
      currentY += 8;
    });

    return currentY;
  }

  generatePDF(result: ScanResult): jsPDF {
    const doc = new jsPDF();
    
    // Add header
    this.addHeader(doc, 'Rapport de Sécurité');
    
    let currentY = 50;
    
    // Add summary section
    currentY = this.addSummarySection(doc, result, currentY);
    currentY += 10;
    
    // Add vulnerabilities section
    currentY = this.addVulnerabilitiesSection(doc, result.vulnerabilities, currentY);
    currentY += 10;
    
    // Add recommendations section
    this.addRecommendationsSection(doc, currentY);
    
    // Add footer to all pages
    const pageCount = doc.getNumberOfPages();
    for (let i = 1; i <= pageCount; i++) {
      doc.setPage(i);
      this.addFooter(doc, i);
    }
    
    return doc;
  }

  downloadPDF(result: ScanResult, filename?: string) {
    const doc = this.generatePDF(result);
    const defaultFilename = `rapport-securite-${new Date().toISOString().split('T')[0]}.pdf`;
    doc.save(filename || defaultFilename);
  }
}

export const pdfGenerator = new PDFGenerator();
