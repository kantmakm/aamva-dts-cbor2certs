import cbor2
import requests
import tempfile
from pathlib import Path
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.exceptions import InvalidSignature


# --- Configuration & Endpoints ---
BASE_URL = "https://vical.dts.aamva.org/"

# Trust Anchor Endpoints
URL_ROOT_CA = 'https://vical.dts.aamva.org/certificates/ca'
URL_INTERMEDIATE_CA = 'https://vical.dts.aamva.org/certificates/ca_intermediate'
URL_VICAL_SIGNER = 'https://vical.dts.aamva.org/certificates/vicalsigner'

# Output Settings
OUTPUT_CERT_DIR = Path('extracted_iacas')
TARGET_FILENAME = "vical.cbor"


# --- Helper Functions ---

def get_current_vical_url(base_url):
    """Scrapes the base URL to find the dynamic link for the current VICAL file."""
    print(f"🔍 Scraping {base_url} for current VICAL link...")
    try:
        response = requests.get(base_url)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"❌ Error fetching the page: {e}")
        return None

    soup = BeautifulSoup(response.content, 'html.parser')
    
    # 1. Find the specific table
    current_vical_table = soup.find('table', id='currentvical')
    if not current_vical_table:
        print("❌ Error: Could not find table with id='currentvical'.")
        return None

    # 2. Find the download button inside that table
    download_link_tag = current_vical_table.find('a', class_='btn btn-primary')
    if not download_link_tag:
        print("❌ Error: Could not find 'btn btn-primary' link inside the table.")
        return None

    # 3. Construct full URL
    relative_url = download_link_tag.get('href')
    if not relative_url:
        print("❌ Error: Link tag missing 'href' attribute.")
        return None
        
    full_download_url = urljoin(base_url, relative_url)
    print(f"✅ Found VICAL URL: {full_download_url}")
    return full_download_url

def download_file(url, destination_path):
    """Downloads a file from a URL to a specified Path object."""
    print(f"⬇️  Downloading {url}...")
    try:
        response = requests.get(url, stream=True)
        response.raise_for_status()
        
        with open(destination_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        return True
    except requests.exceptions.RequestException as e:
        print(f"❌ Download failed: {e}")
        return False

def load_cert_from_pem(file_path):
    """Loads a certificate from a PEM file."""
    try:
        with open(file_path, 'rb') as f:
            return x509.load_pem_x509_certificate(f.read())
    except FileNotFoundError:
        print(f"❌ Certificate file not found: {file_path}")
        return None
    except ValueError:
        print(f"❌ Could not parse PEM certificate: {file_path}")
        return None

def load_vical_file(file_path):
    """Loads and decodes the CBOR VICAL structure."""
    try:
        with open(file_path, 'rb') as f:
            return cbor2.load(f)
    except (FileNotFoundError, cbor2.CBORDecodeError) as e:
        print(f"❌ Error loading VICAL file: {e}")
        return None

# --- Core Logic ---

def process_vical(vical_data, root_ca_cert, intermediate_ca_cert, vsc_cert):
    """
    Verifies the cert chain and the COSE_Sign1 signature of the VICAL payload.
    Handles Raw-to-DER signature conversion for COSE compliance.
    """
    if not isinstance(vical_data, list) or len(vical_data) < 4:
        print("❌ VICAL structure invalid (expected list of length 4+).")
        return

    try:
        # COSE_Sign1 Structure: [protected_headers, unprotected_headers, payload, signature]
        protected_headers_bytes = vical_data[0]
        payload = vical_data[2]
        raw_signature = vical_data[3]
        
        print("\n🔐 Verifying Trust Chain...")
        
        # 1. Verify VICAL Signer (VSC) using Intermediate CA
        # (X.509 certs use DER signatures natively, so this usually just works)
        intermediate_ca_cert.public_key().verify(
            vsc_cert.signature,
            vsc_cert.tbs_certificate_bytes,
            ec.ECDSA(vsc_cert.signature_hash_algorithm),
        )
        print("   ✅ VICAL Signer is trusted by Intermediate CA.")

        # 2. Verify Intermediate CA using Root CA
        root_ca_cert.public_key().verify(
            intermediate_ca_cert.signature,
            intermediate_ca_cert.tbs_certificate_bytes,
            ec.ECDSA(intermediate_ca_cert.signature_hash_algorithm),
        )
        print("   ✅ Intermediate CA is trusted by Root CA.")
        
        print("\n🔐 Verifying VICAL COSE Signature...")

        # --- A. Determine Hash Algorithm from Protected Headers ---
        # Decode the protected header to find the 'alg' ID
        ph_map = cbor2.loads(protected_headers_bytes)
        alg_id = ph_map.get(1) # Label 1 is 'alg'
        
        # Default to SHA256 (ES256), but handle others
        if alg_id == -7:  # ES256
            hash_alg = hashes.SHA256()
            curve_size = 32 # bytes (256 bits)
            print("      -> Algorithm: ES256 (SHA-256)")
        elif alg_id == -35: # ES384
            hash_alg = hashes.SHA384()
            curve_size = 48 # bytes (384 bits)
            print("      -> Algorithm: ES384 (SHA-384)")
        else:
            print(f"      ⚠️ Unknown Algorithm ID: {alg_id}. Defaulting to SHA256.")
            hash_alg = hashes.SHA256()
            curve_size = 32

        # --- B. Convert Signature from Raw (COSE) to DER (Python/OpenSSL) ---
        # COSE Signatures are R || S (Raw concatenation).
        # Python verify() expects ASN.1 DER.
        if len(raw_signature) != (curve_size * 2):
            print(f"      ⚠️ Warning: Signature length {len(raw_signature)} does not match expected {curve_size*2}.")
        
        r = int.from_bytes(raw_signature[:curve_size], byteorder='big')
        s = int.from_bytes(raw_signature[curve_size:], byteorder='big')
        der_signature = utils.encode_dss_signature(r, s)

        # --- C. Construct Sig_Structure and Verify ---
        # Structure: ['Signature1', protected_body_bytes, external_aad, payload_bytes]
        sig_structure = ['Signature1', protected_headers_bytes, b'', payload]
        tbs_data = cbor2.dumps(sig_structure)

        vsc_cert.public_key().verify(
            der_signature, # Use the converted DER signature
            tbs_data,
            ec.ECDSA(hash_alg) 
        )
        print("   ✅ VICAL Payload signature is VALID.")

        # 3. Decode Payload and Extract
        decoded_records = cbor2.loads(payload)
        final_records_list = decoded_records.get('certificateInfos')
        extract_and_save_iacas(final_records_list)

    except InvalidSignature:
        print("❌ CRITICAL: Signature validation FAILED. The VICAL file may be tampered with.")
    except Exception as e:
        print(f"❌ Unexpected error in processing: {e}")
        
def extract_and_save_iacas(issuer_records):
    """Iterates through records, names them, and saves to disk."""
    if not issuer_records:
        print("❌ No certificates found in payload.")
        return

    # Create output directory
    OUTPUT_CERT_DIR.mkdir(parents=True, exist_ok=True)

    # Map for friendly names
    rename_map = {
        'alaska_dmv_iaca.pem': 'ak_certificate.pem',
        'carswsnpdojmtgov.pem': 'mt_certificate.pem',
        'colorado_root_certificate.pem': 'co_certificate.pem',
        'fast_enterprises_root.pem': 'md_certificate.pem',
        'georgia_root_certificate_authority.pem': 'ga_certificate.pem',
        'httpspartnermdldotndgov.pem': 'nd_certificate.pem',
        'mvmprodca.pem': 'az_certificate.pem',
        'iaca-utah-usa.pem': 'ut_certificate.pem',
        'va_mid_iaca.pem': 'va_certificate.pem',
        'mdot_mva_mdl_root.pem': 'md_certificate.pem'
    }

    print(f"\n📂 Extracting {len(issuer_records)} certificates to '{OUTPUT_CERT_DIR}'...")

    for record in issuer_records:
        # Handle inconsistent keys in source data
        cert_der = record.get('certificate') or record.get('iaca')
        if not cert_der:
            continue

        try:
            cert = x509.load_der_x509_certificate(cert_der)
            
            # Get Common Name (CN) for filename
            cn_attr = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
            
            if cn_attr:
                # Sanitize filename
                raw_name = cn_attr[0].value
                safe_name = "".join(c for c in raw_name if c.isalnum() or c in (' ', '-')).strip().replace(' ', '_').lower()
                filename = f"{safe_name}.pem"
            else:
                filename = "unknown_issuer.pem"

            # Apply rename map
            filename = rename_map.get(filename, filename)
            
            # Handle duplicates
            file_path = OUTPUT_CERT_DIR / filename
            counter = 1
            while file_path.exists():
                file_path = OUTPUT_CERT_DIR / f"{counter}_{filename}"
                counter += 1

            # Save
            with open(file_path, 'wb') as f:
                f.write(cert.public_bytes(encoding=serialization.Encoding.PEM))
            
            print(f"  -> Saved: {file_path.name}")

        except Exception as e:
            print(f"  -> ⚠️ Failed to save a certificate: {e}")

# --- Main Execution ---

if __name__ == "__main__":
    print("--- 🚀 VICAL Extraction Script ---")

    # 1. Scrape the URL first
    vical_file_url = get_current_vical_url(BASE_URL)
    if not vical_file_url:
        print("❌ Could not determine VICAL URL. Exiting.")
        exit(1)

    # 2. Create Temporary Directory (Auto-cleans up on exit)
    with tempfile.TemporaryDirectory() as temp_dir_str:
        temp_dir = Path(temp_dir_str)
        print(f"\nCreated temp workspace: {temp_dir}")

        # Define temporary paths
        paths = {
            'root': temp_dir / 'ca_root.crt',
            'inter': temp_dir / 'ca_intermediate.crt',
            'vsc': temp_dir / 'vicalsigner.crt',
            'vical': temp_dir / 'aamva_vical.cbor'
        }

        # 3. Download everything
        downloads_ok = all([
            download_file(URL_ROOT_CA, paths['root']),
            download_file(URL_INTERMEDIATE_CA, paths['inter']),
            download_file(URL_VICAL_SIGNER, paths['vsc']),
            download_file(vical_file_url, paths['vical'])
        ])

        if not downloads_ok:
            print("\n❌ Critical download failed. Exiting.")
            exit(1)

        # 4. Load Certificates
        root_ca = load_cert_from_pem(paths['root'])
        inter_ca = load_cert_from_pem(paths['inter'])
        vsc_cert = load_cert_from_pem(paths['vsc'])

        if not (root_ca and inter_ca and vsc_cert):
            print("\n❌ Failed to load trust chain certificates.")
            exit(1)

        # 5. Load VICAL Data
        vical_data = load_vical_file(paths['vical'])
        if not vical_data:
            exit(1)

        # 6. Process
        process_vical(vical_data, root_ca, inter_ca, vsc_cert)

    print("\n--- ✅ Script Finished ---")