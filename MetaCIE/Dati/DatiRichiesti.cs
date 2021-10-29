using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using System.Xml;

namespace MetaCIE.Dati
{
    public class DatiRichiesti
    {
        public string passwordCertificato;
        public X509Certificate2 x509;
        public byte[] x509Byte;
        public XmlDocument metadata;
     
    }
}
