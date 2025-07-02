import { Button } from "@/components/ui/button";
import { ArrowLeft, Shield } from "lucide-react";
import { Link } from "react-router-dom";
import Footer from "@/components/Footer";

const MentionsLegales = () => {
  return (
    <div className="min-h-screen">
      <div className="container mx-auto px-4 py-8">
        {/* Header */}
        <div className="flex items-center justify-between mb-8">
          <Link to="/" className="flex items-center space-x-3">
            <Shield className="h-8 w-8 text-purple-400" />
            <span className="text-2xl font-bold text-white">Securicheck</span>
          </Link>
          <Link to="/">
            <Button className="bg-purple-600 hover:bg-purple-700 text-white border-0">
              <ArrowLeft className="h-4 w-4 mr-2" />
              Retour à l'accueil
            </Button>
          </Link>
        </div>

        {/* Content */}
        <div className="max-w-4xl mx-auto">
          <div className="bg-white/10 backdrop-blur-sm rounded-2xl p-8 border border-white/20">
            <h1 className="text-3xl font-bold text-white mb-8">Mentions Légales</h1>
            
            <div className="space-y-6 text-slate-300">
              <section>
                <h2 className="text-xl font-semibold text-white mb-3">Éditeur du site</h2>
                <p>
                  <strong>Nom :</strong> Securicheck<br />
                  <strong>Adresse :</strong> [À compléter]<br />
                  <strong>Email :</strong> contact@securicheck.com<br />
                  <strong>Téléphone :</strong> [À compléter]
                </p>
              </section>

              <section>
                <h2 className="text-xl font-semibold text-white mb-3">Hébergement</h2>
                <p>
                  Ce site est hébergé par :<br />
                  <strong>Hébergeur :</strong> [À compléter]<br />
                  <strong>Adresse :</strong> [À compléter]
                </p>
              </section>

              <section>
                <h2 className="text-xl font-semibold text-white mb-3">Propriété intellectuelle</h2>
                <p>
                  L'ensemble de ce site relève de la législation française et internationale sur le droit d'auteur et la propriété intellectuelle. 
                  Tous les droits de reproduction sont réservés, y compris pour les documents téléchargeables et les représentations iconographiques et photographiques.
                </p>
              </section>

              <section>
                <h2 className="text-xl font-semibold text-white mb-3">Responsabilité</h2>
                <p>
                  Les informations contenues sur ce site sont aussi précises que possible et le site remis à jour à différentes périodes de l'année, 
                  mais peut toutefois contenir des inexactitudes ou des omissions. Si vous constatez une lacune, erreur ou ce qui parait être un dysfonctionnement, 
                  merci de bien vouloir le signaler par email, à l'adresse contact@securicheck.com, en décrivant le problème de la façon la plus précise possible.
                </p>
              </section>

              <section>
                <h2 className="text-xl font-semibold text-white mb-3">Données personnelles</h2>
                <p>
                  Ce site ne collecte aucune donnée personnelle. Les analyses de sécurité sont effectuées de manière anonyme et aucune information 
                  n'est stockée sur nos serveurs. Toutes les données sont traitées localement dans votre navigateur.
                </p>
              </section>

              <section>
                <h2 className="text-xl font-semibold text-white mb-3">Cookies</h2>
                <p>
                  Ce site n'utilise pas de cookies de tracking ou de publicité. Seuls les cookies techniques nécessaires au fonctionnement 
                  du site peuvent être utilisés.
                </p>
              </section>
            </div>
          </div>
        </div>
      </div>
      <Footer />
    </div>
  );
};

export default MentionsLegales;
