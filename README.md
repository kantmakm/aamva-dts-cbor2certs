Setup python venv:
python3 -m venv venv

Activate the venv:
source venv/bin/activate

install libs:
pip3 install cbor2 cryptography requests

run the script:
(venv) bash-3.2$ python3 ex_certs_v2.py 

--- VICAL Decoding and Extraction Script ---

Created temporary directory: /var/folders/xr/gp59cg0s4vjcb643tlyxq9lw0000gp/T/tmpkf6p5i6a
Downloading ca_root.crt from https://vical.dts.aamva.org/certificates/ca...
✅ Successfully saved to /var/folders/xr/gp59cg0s4vjcb643tlyxq9lw0000gp/T/tmpkf6p5i6a/ca_root.crt
Downloading ca_intermediate.crt from https://vical.dts.aamva.org/certificates/ca_intermediate...
✅ Successfully saved to /var/folders/xr/gp59cg0s4vjcb643tlyxq9lw0000gp/T/tmpkf6p5i6a/ca_intermediate.crt
Downloading vicalsigner.crt from https://vical.dts.aamva.org/certificates/vicalsigner...
✅ Successfully saved to /var/folders/xr/gp59cg0s4vjcb643tlyxq9lw0000gp/T/tmpkf6p5i6a/vicalsigner.crt
Downloading aamva_vical.cbor from https://vical.dts.aamva.org/vical/vc/...
✅ Successfully saved to /var/folders/xr/gp59cg0s4vjcb643tlyxq9lw0000gp/T/tmpkf6p5i6a/aamva_vical.cbor

--- Starting Processing ---
✅ DTS Root CA loaded: CN=AAMVA DTS Root CA,OU=Certification Authorities,O=American Association of Motor Vehicle Administrators,C=US
✅ DTS Intermediate CA loaded: CN=AAMVA DTS Issuing CA,OU=Certification Authorities,O=American Association of Motor Vehicle Administrators,C=US
✅ VICAL Signer Certificate loaded: CN=AAMVA Prod Vical-Signer-01,O=American Association of Motor Vehicle Administrators,C=US
✅ VICAL CBOR file successfully parsed.

Verifying certificate chain...
✅ VSC is trusted by the Intermediate CA.
✅ Intermediate CA is trusted by the Root CA.
✅ Full certificate chain is valid!

⚠️ SKIPPING final signature validation of VICAL data.

Found 14 issuer certificates. Extracting and renaming...
  -> ✅ Extracted and saved 'CN=Fast Enterprises Root,O=Maryland MVA,L=Glen Burnie,C=US,ST=US-MD' to extracted_iacas/3_md_certificate.pem (renamed from fast_enterprises_root.pem)
  -> ✅ Extracted and saved 'C=US,ST=US-UT,O=Utah DLD,CN=IACA-UTAH-USA' to extracted_iacas/3_ut_certificate.pem (renamed from iaca-utah-usa.pem)
  -> ✅ Extracted and saved 'C=US,ST=US-VA,CN=VA mID IACA' to extracted_iacas/2_va_certificate.pem (renamed from va_mid_iaca.pem)
  -> ✅ Extracted and saved 'C=US,ST=US-VA,CN=VA mID IACA-A' to extracted_iacas/2_va_mid_iaca-a.pem (renamed from va_mid_iaca-a.pem)
  -> ✅ Extracted and saved 'CN=Colorado Root Certificate,OU=CO DRIVES,O=Colorado Department of Revenue,L=Denver,C=US,ST=US-CO' to extracted_iacas/2_co_certificate.pem (renamed from colorado_root_certificate.pem)
  -> ✅ Extracted and saved 'CN=Georgia Root Certificate Authority,OU=DRIVES,O=Georgia Department of Driver Services,L=Conyers,C=US,ST=US-GA' to extracted_iacas/2_ga_certificate.pem (renamed from georgia_root_certificate_authority.pem)
  -> ✅ Extracted and saved 'C=US,ST=AK,O=Alaska DMV,CN=Alaska DMV IACA' to extracted_iacas/2_ak_certificate.pem (renamed from alaska_dmv_iaca.pem)
  -> ✅ Extracted and saved 'CN=https://partner.mdl.dot.nd.gov/,OU=LEGEND,O=North Dakota Department of Transportation,L=Bismarck,C=US,ST=US-ND' to extracted_iacas/2_nd_certificate.pem (renamed from httpspartnermdldotndgov.pem)
  -> ✅ Extracted and saved 'C=US,ST=US-UT,O=Utah DLD,CN=IACA-UTAH-USA' to extracted_iacas/4_ut_certificate.pem (renamed from iaca-utah-usa.pem)
  -> ✅ Extracted and saved 'L=Phoenix,ST=US-AZ,C=US,OU=IT,O=Arizona Department of Transportation,CN=MVMProdCA' to extracted_iacas/4_az_certificate.pem (renamed from mvmprodca.pem)
  -> ✅ Extracted and saved 'L=Phoenix,ST=US-AZ,C=US,OU=IT,O=Arizona Department of Transportation,CN=MVMProdCA' to extracted_iacas/5_az_certificate.pem (renamed from mvmprodca.pem)
  -> ✅ Extracted and saved 'L=Phoenix,ST=US-AZ,C=US,OU=IT,O=Arizona Department of Transportation,CN=MVMProdCA' to extracted_iacas/6_az_certificate.pem (renamed from mvmprodca.pem)
  -> ✅ Extracted and saved 'CN=carswsnp.dojmt.gov,OU=Montana Motor Vehicle Division,O=Montana Department of Justice,L=Helena,C=US,ST=US-MT' to extracted_iacas/2_mt_certificate.pem (renamed from carswsnpdojmtgov.pem)
  -> ✅ Extracted and saved 'CN=MDOT MVA mDL Root,O=Maryland MVA,L=Glen Burnie,C=US,ST=US-MD' to extracted_iacas/4_md_certificate.pem (renamed from mdot_mva_mdl_root.pem)

✅ Cleaned up temporary directory: /var/folders/xr/gp59cg0s4vjcb643tlyxq9lw0000gp/T/tmpkf6p5i6a

--- Script finished. ---
