using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Threading.Tasks;
using System.Xml;

namespace MetaCIE.Metadata
{
    class SignedXmlWithID : SignedXml
    {
        public SignedXmlWithID(XmlDocument xml) : base(xml)
        {
        }

        public SignedXmlWithID(System.Xml.XmlElement xmlElement)
        : base(xmlElement)
        {
        }


        public override XmlElement GetIdElement(XmlDocument doc, string id)
        {

            XmlElement idElem = base.GetIdElement(doc, id);

            if (idElem == null)
            {
                XmlNamespaceManager nsManager = new XmlNamespaceManager(doc.NameTable);
                nsManager.AddNamespace("wsu", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd");

                idElem = doc.SelectSingleNode("//*[@wsu:Id=\"" + id + "\"]", nsManager) as XmlElement;
            }

            return idElem;
        }



    }


}
