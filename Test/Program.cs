using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Test
{
    class Program
    {
        static void Main(string[] args)
        {

            MetaCIE .Metadata.MetadataInfo info = new MetaCIE.Metadata.MetadataInfo();
            info.assertion_consumer_service_url = "https://sspidSP.spProvider.it/login";
            info.logout_service_url = "https://spidSP.spProvider.it/login";
            info.url_ente = "https://spidSP.spProvider.it";
            info.codiceIPA = "C_c000";
            info.denominazione_ente = "Comune di Roma";
            info.ENTITY_ID = "https://spidSP.spProvider.it";
            info.emailAddress = "info@cmnroma.it";
            info.nomeServizi = "Accesso ai servizi";
            info.Istat = "000000";
            info.UUID = Guid.NewGuid().ToString();
            MetaCIE.Manager manager = new MetaCIE.Manager();
            var obj = manager.Crea(info);
            System.IO.File.WriteAllBytes("c:\\temp\\certificatoCIE.pfx", obj.x509Byte);
            System.IO.File.WriteAllText("c:\\temp\\PasswordCertificatoCIE.txt", obj.passwordCertificato);
            System.IO.File.WriteAllText("c:\\temp\\metadataCIE.xml", obj.metadata.OuterXml);

        }
    }
}
