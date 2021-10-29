using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MetaCIE
{
    using System;
    using System.Security.Cryptography.X509Certificates;
    using System.Web.Security;
  

    public class Manager
    {
        public Dati.DatiRichiesti Crea(Metadata.MetadataInfo info)
        {

            if (info == null)
            {
                throw new Exception("MetadataInfo obbligatorio");
            }
            if (string.IsNullOrEmpty(info.assertion_consumer_service_url))
            {
                throw new Exception("assertion_consumer_service_url obbligatorio");
            }
            if (string.IsNullOrEmpty(info.codiceIPA ))
            {
                throw new Exception("codiceIPA obbligatorio");
            }
            if (string.IsNullOrEmpty(info.denominazione_ente ))
            {
                throw new Exception("denominazione_ente obbligatorio");
            }
            if (string.IsNullOrEmpty(info.emailAddress ))
            {
                throw new Exception("emailAddress obbligatorio");
            }
            if (string.IsNullOrEmpty(info.ENTITY_ID ))
            {
                throw new Exception("ENTITY_ID obbligatorio");
            }
            if (string.IsNullOrEmpty(info.logout_service_url ))
            {
                throw new Exception("logout_service_url obbligatorio");
            }
            if (string.IsNullOrEmpty(info.nomeServizi))
            {
                throw new Exception("nomeServizi obbligatorio");
            }

            if (string.IsNullOrEmpty(info.url_ente ))
            {
                throw new Exception("url_ente");
            }


            string passwordCertificato = Membership.GeneratePassword(10, 1);
            string CommonName = info.ENTITY_ID;
            string OrganizationName =  info.denominazione_ente;
            string OrganizationIdentifier = string.Format("PA:IT-{0}", info.codiceIPA);
            string countryName = "IT";
            string LocalityName = info.denominazione_ente;
            string attr = string.Format("2.5.4.3={0}," + "2.5.4.10={1}," + "2.5.4.97={2}," + "2.5.4.6=IT," + "2.5.4.7={3}", CommonName, OrganizationName, OrganizationIdentifier, LocalityName);
            byte[] byteCert= Certificate.CreateCertificate.Main(attr, passwordCertificato);
            X509Certificate2 x509 = new X509Certificate2(byteCert, passwordCertificato, X509KeyStorageFlags.Exportable);
            Metadata.CreateMetadata Metadata = new Metadata.CreateMetadata(x509, info);
            System.Xml.XmlDocument doc = Metadata.getCIE();
            Dati.DatiRichiesti obj = new Dati.DatiRichiesti();
            obj.x509 = x509;
            obj.metadata = doc;
            obj.x509Byte = byteCert;
            obj.passwordCertificato = passwordCertificato;
            return obj;

        }

   }

}
