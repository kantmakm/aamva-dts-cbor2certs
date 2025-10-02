# **AAMVA VICAL Certificate Extraction Guide**

This guide outlines the process for setting up a Python environment and running a script to download and extract root certificates from the AAMVA Digital Trust Service (DTS) Verified Issuer Certificate Authority List (VICAL).

### **1\. Environment Setup**

First, create and activate a Python virtual environment to manage the necessary libraries.

**Setup Python venv:**

python3 \-m venv venv

**Activate the venv:**

source venv/bin/activate

**Install required libraries:**

pip3 install cbor2 cryptography requests

### **2\. Run the Extraction Script**

Once the environment is active, execute the Python script to begin the download and extraction process.

(venv) bash-3.2$ python3 ex\_certs\_v2.py

### **3\. Example Script Output**

The script will first download the necessary certificates and the VICAL file into a temporary directory. It will then validate the certificate chain and extract the individual issuer certificates into a local folder named extracted\_iacas.

\--- VICAL Decoding and Extraction Script \---

Created temporary directory: /var/folders/xr/gp59cg0s4vjcb643tlyxq9lw0000gp/T/tmpkf6p5i6a  
Downloading ca\_root.crt from \[https://vical.dts.aamva.org/certificates/ca\](https://vical.dts.aamva.org/certificates/ca)...  
✅ Successfully saved to /var/folders/xr/gp59cg0s4vjcb643tlyxq9lw0000gp/T/tmpkf6p5i6a/ca\_root.crt  
Downloading ca\_intermediate.crt from \[https://vical.dts.aamva.org/certificates/ca\_intermediate\](https://vical.dts.aamva.org/certificates/ca\_intermediate)...  
✅ Successfully saved to /var/folders/xr/gp59cg0s4vjcb643tlyxq9lw0000gp/T/tmpkf6p5i6a/ca\_intermediate.crt  
Downloading vicalsigner.crt from \[https://vical.dts.aamva.org/certificates/vicalsigner\](https://vical.dts.aamva.org/certificates/vicalsigner)...  
✅ Successfully saved to /var/folders/xr/gp59cg0s4vjcb643tlyxq9lw0000gp/T/tmpkf6p5i6a/vicalsigner.crt  
Downloading aamva\_vical.cbor from \[https://vical.dts.aamva.org/vical/vc/\](https://vical.dts.aamva.org/vical/vc/)...  
✅ Successfully saved to /var/folders/xr/gp59cg0s4vjcb643tlyxq9lw0000gp/T/tmpkf6p5i6a/aamva\_vical.cbor

\--- Starting Processing \---  
✅ DTS Root CA loaded: CN=AAMVA DTS Root CA,OU=Certification Authorities,O=American Association of Motor Vehicle Administrators,C=US  
✅ DTS Intermediate CA loaded: CN=AAMVA DTS Issuing CA,OU=Certification Authorities,O=American Association of Motor Vehicle Administrators,C=US  
✅ VICAL Signer Certificate loaded: CN=AAMVA Prod Vical-Signer-01,O=American Association of Motor Vehicle Administrators,C=US  
✅ VICAL CBOR file successfully parsed.

Verifying certificate chain...  
✅ VSC is trusted by the Intermediate CA.  
✅ Intermediate CA is trusted by the Root CA.  
✅ Full certificate chain is valid\!

⚠️ SKIPPING final signature validation of VICAL data.

Found 14 issuer certificates. Extracting and renaming...  
  \-\> ✅ Extracted and saved 'CN=Fast Enterprises Root,O=Maryland MVA,L=Glen Burnie,C=US,ST=US-MD' to extracted\_iacas/3\_md\_certificate.pem (renamed from fast\_enterprises\_root.pem)  
  \-\> ✅ Extracted and saved 'C=US,ST=US-UT,O=Utah DLD,CN=IACA-UTAH-USA' to extracted\_iacas/3\_ut\_certificate.pem (renamed from iaca-utah-usa.pem)  
  \-\> ✅ Extracted and saved 'C=US,ST=US-VA,CN=VA mID IACA' to extracted\_iacas/2\_va\_certificate.pem (renamed from va\_mid\_iaca.pem)  
  \-\> ✅ Extracted and saved 'C=US,ST=US-VA,CN=VA mID IACA-A' to extracted\_iacas/2\_va\_mid\_iaca-a.pem (renamed from va\_mid\_iaca-a.pem)  
  \-\> ✅ Extracted and saved 'CN=Colorado Root Certificate,OU=CO DRIVES,O=Colorado Department of Revenue,L=Denver,C=US,ST=US-CO' to extracted\_iacas/2\_co\_certificate.pem (renamed from colorado\_root\_certificate.pem)  
  \-\> ✅ Extracted and saved 'CN=Georgia Root Certificate Authority,OU=DRIVES,O=Georgia Department of Driver Services,L=Conyers,C=US,ST=US-GA' to extracted\_iacas/2\_ga\_certificate.pem (renamed from georgia\_root\_certificate\_authority.pem)  
  \-\> ✅ Extracted and saved 'C=US,ST=AK,O=Alaska DMV,CN=Alaska DMV IACA' to extracted\_iacas/2\_ak\_certificate.pem (renamed from alaska\_dmv\_iaca.pem)  
  \-\> ✅ Extracted and saved 'CN=\[https://partner.mdl.dot.nd.gov/,OU=LEGEND,O=North\](https://partner.mdl.dot.nd.gov/,OU=LEGEND,O=North) Dakota Department of Transportation,L=Bismarck,C=US,ST=US-ND' to extracted\_iacas/2\_nd\_certificate.pem (renamed from httpspartnermdldotndgov.pem)  
  \-\> ✅ Extracted and saved 'C=US,ST=US-UT,O=Utah DLD,CN=IACA-UTAH-USA' to extracted\_iacas/4\_ut\_certificate.pem (renamed from iaca-utah-usa.pem)  
  \-\> ✅ Extracted and saved 'L=Phoenix,ST=US-AZ,C=US,OU=IT,O=Arizona Department of Transportation,CN=MVMProdCA' to extracted\_iacas/4\_az\_certificate.pem (renamed from mvmprodca.pem)  
  \-\> ✅ Extracted and saved 'L=Phoenix,ST=US-AZ,C=US,OU=IT,O=Arizona Department of Transportation,CN=MVMProdCA' to extracted\_iacas/5\_az\_certificate.pem (renamed from mvmprodca.pem)  
  \-\> ✅ Extracted and saved 'L=Phoenix,ST=US-AZ,C=US,OU=IT,O=Arizona Department of Transportation,CN=MVMProdCA' to extracted\_iacas/6\_az\_certificate.pem (renamed from mvmprodca.pem)  
  \-\> ✅ Extracted and saved 'CN=carswsnp.dojmt.gov,OU=Montana Motor Vehicle Division,O=Montana Department of Justice,L=Helena,C=US,ST=US-MT' to extracted\_iacas/2\_mt\_certificate.pem (renamed from carswsnpdojmtgov.pem)  
  \-\> ✅ Extracted and saved 'CN=MDOT MVA mDL Root,O=Maryland MVA,L=Glen Burnie,C=US,ST=US-MD' to extracted\_iacas/4\_md\_certificate.pem (renamed from mdot\_mva\_mdl\_root.pem)

✅ Cleaned up temporary directory: /var/folders/xr/gp59cg0s4vjcb643tlyxq9lw0000gp/T/tmpkf6p5i6a

\--- Script finished. \---

### **4\. Post-Processing for Android Integration**

If the extracted certificates will be imported into an Android application for verifying state-issued mDL credentials, you will want to run the ren.sh script inside the extracted\_iacas directory to update the certificate filenames to the required format.
