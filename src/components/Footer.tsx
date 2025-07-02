import { Link } from "react-router-dom";

const Footer = () => {
  return (
    <footer className="mt-16 border-t border-white/20 bg-black/20 backdrop-blur-sm">
      <div className="container mx-auto px-4 py-6">
        <div className="flex flex-col md:flex-row justify-between items-center space-y-4 md:space-y-0">
          <div className="text-slate-400 text-sm">
            © 2024 Securicheck - Outil d'analyse de sécurité web
          </div>
          <div className="flex space-x-6">
            <Link 
              to="/mentions-legales" 
              className="text-slate-400 hover:text-white text-sm transition-colors duration-200"
            >
              Mentions légales
            </Link>
            <Link 
              to="/conditions-generales" 
              className="text-slate-400 hover:text-white text-sm transition-colors duration-200"
            >
              Conditions générales
            </Link>
          </div>
        </div>
      </div>
    </footer>
  );
};

export default Footer;
