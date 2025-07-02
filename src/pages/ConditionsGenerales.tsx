import { Button } from "@/components/ui/button";
import { ArrowLeft, Shield } from "lucide-react";
import { Link } from "react-router-dom";
import Footer from "@/components/Footer";

const ConditionsGenerales = () => {
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
            <h1 className="text-3xl font-bold text-white mb-8">Conditions Générales d'Utilisation</h1>
            
            <div className="space-y-6 text-slate-300">
              <section>
                <h2 className="text-xl font-semibold text-white mb-3">1. Présentation du site</h2>
                <p>
                  Le site SecuriCheck a pour objectif de fournir des outils d'analyse automatique permettant d'évaluer la sécurité, la performance et la conformité technique des sites web.
                </p>
                <p className="mt-3">
                  Le site est édité par Estiam Bourges, situé à 52 Av. de la Libération, 18000 Bourges, immatriculé sous le numéro 775 020 175 000 11, contact : bourges@estiam.com.
                </p>
              </section>

              <section>
                <h2 className="text-xl font-semibold text-white mb-3">2. Objet des CGU</h2>
                <p>
                  Les présentes Conditions Générales d'Utilisation ont pour but de définir les modalités d'utilisation des services proposés par SecuriCheck. Toute navigation ou utilisation du Site implique l'acceptation sans réserve des présentes CGU.
                </p>
              </section>

              <section>
                <h2 className="text-xl font-semibold text-white mb-3">3. Services proposés</h2>
                <p>Le Site propose notamment :</p>
                <ul className="list-disc list-inside mt-3 space-y-2">
                  <li>Le scan automatique de sites web pour détecter des failles de sécurité potentielles,</li>
                  <li>L'analyse de performance et de bonnes pratiques (SEO, accessibilité, etc.),</li>
                  <li>Des recommandations d'amélioration.</li>
                </ul>
                <p className="mt-3">
                  <strong>Attention :</strong> Le Site fournit une aide à l'audit mais ne garantit pas une détection exhaustive des vulnérabilités.
                </p>
              </section>

              <section>
                <h2 className="text-xl font-semibold text-white mb-3">4. Accès et responsabilité</h2>
                <p>L'utilisation des services du Site est libre d'accès, sauf indication contraire.</p>
                <p className="mt-3">L'utilisateur s'engage à :</p>
                <ul className="list-disc list-inside mt-3 space-y-2">
                  <li>Ne scanner que des sites dont il est propriétaire ou pour lesquels il dispose d'une autorisation explicite,</li>
                  <li>Ne pas détourner les outils du Site à des fins de piratage ou d'intrusion malveillante,</li>
                  <li>Ne pas utiliser le Site pour nuire à des tiers.</li>
                </ul>
                <p className="mt-3">
                  Le non-respect de ces règles pourra entraîner la suspension immédiate de l'accès au Site.
                </p>
              </section>

              <section>
                <h2 className="text-xl font-semibold text-white mb-3">5. Propriété intellectuelle</h2>
                <p>
                  L'ensemble du contenu (logos, textes, scripts, fonctionnalités) est protégé par le droit de la propriété intellectuelle et reste la propriété exclusive de SecuriCheck ou de ses partenaires.
                </p>
                <p className="mt-3">
                  Toute reproduction ou réutilisation sans autorisation est interdite.
                </p>
              </section>

              <section>
                <h2 className="text-xl font-semibold text-white mb-3">6. Limitation de responsabilité</h2>
                <p>
                  Le Site fournit des résultats à titre informatif. Bien que les analyses soient basées sur des techniques reconnues, SecuriCheck ne saurait être tenu responsable :
                </p>
                <ul className="list-disc list-inside mt-3 space-y-2">
                  <li>D'un usage inapproprié des résultats,</li>
                  <li>D'un faux positif ou d'un oubli de détection,</li>
                  <li>De tout dommage consécutif à une mauvaise interprétation.</li>
                </ul>
              </section>

              <section>
                <h2 className="text-xl font-semibold text-white mb-3">7. Interruption ou modification du service</h2>
                <p>
                  SecuriCheck se réserve le droit d'interrompre temporairement ou définitivement l'accès au site ou de modifier ses fonctionnalités, sans préavis.
                </p>
              </section>

              <section>
                <h2 className="text-xl font-semibold text-white mb-3">8. Droit applicable et juridiction</h2>
                <p>
                  Les présentes CGU sont régies par le droit français. Tout litige relatif à l'utilisation du Site sera soumis à la compétence des tribunaux français.
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

export default ConditionsGenerales;
