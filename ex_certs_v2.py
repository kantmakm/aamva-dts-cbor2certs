import cbor2
import os
import requests
import tempfile
import shutil
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature
import pprint

# --- NEW: AAMVA DTS Endpoints ---
URL_ROOT_CA = 'https://vical.dts.aamva.org/certificates/ca'
URL_INTERMEDIATE_CA = 'https://vical.dts.aamva.org/certificates/ca_intermediate'
URL_VICAL_SIGNER = 'https://vical.dts.aamva.org/certificates/vicalsigner'
#TODO: determine if there is an endpoint - DONE
#URL_VICAL_FILE = 'https://vical.dts.aamva.org/vical/vc/vc-2025-09-27-1758957681255'
URL_VICAL_FILE = 'https://vical.dts.aamva.org/vical/vc/vc-2025-11-18-1763491092481' #'https://vical.dts.aamva.org/vical/vc/'

# --- Configuration ---
OUTPUT_CERT_DIR = 'extracted_iacas'

# --- NEW: Helper function to download files ---
def download_file(url, destination):
    """Downloads a file from a URL to a specified destination."""
    try:
        print(f"Downloading {os.path.basename(destination)} from {url}...")
        response = requests.get(url, timeout=10)
        response.raise_for_status()  # Raises an HTTPError for bad responses (4xx or 5xx)
        with open(destination, 'wb') as f:
            f.write(response.content)
        print(f"✅ Successfully saved to {destination}")
        return True
    except requests.exceptions.RequestException as e:
        print(f"❌ Failed to download {url}. Error: {e}")
        return False

def load_cert_from_pem(file_path):
    """Loads a certificate from a PEM/CRT file."""
    try:
        with open(file_path, 'rb') as f:
            return x509.load_pem_x509_certificate(f.read())
    except FileNotFoundError:
        print(f"❌ Error: Certificate file not found at '{file_path}'")
        return None

def load_vical_file(file_path):
    """Loads and decodes the outer VICAL CBOR structure."""
    try:
        with open(file_path, 'rb') as f:
            return cbor2.load(f)
    except FileNotFoundError:
        print(f"❌ Error: VICAL file not found at '{file_path}'")
        return None
    except cbor2.CBORDecodeError as e:
        print(f"❌ Error decoding CBOR file: {e}")
        return None

def process_vical(vical_data, root_ca_cert, intermediate_ca_cert, vsc_cert):
    """Verifies the cert chain and extracts certificates, SKIPPING final signature validation."""
    if not isinstance(vical_data, list) or len(vical_data) < 4:
        print(f"❌ VICAL structure is not a list with at least 4 elements as expected.")
        return

    try:
        payload_with_certs = vical_data[2]

        if not isinstance(payload_with_certs, bytes):
             print(f"❌ Error: Expected payload at index 2 to be bytes, but it was {type(payload_with_certs).__name__}")
             return

        print("\nVerifying certificate chain...")
        intermediate_ca_cert.public_key().verify(
            vsc_cert.signature,
            vsc_cert.tbs_certificate_bytes,
            ec.ECDSA(vsc_cert.signature_hash_algorithm),
        )
        print("✅ VSC is trusted by the Intermediate CA.")

        root_ca_cert.public_key().verify(
            intermediate_ca_cert.signature,
            intermediate_ca_cert.tbs_certificate_bytes,
            ec.ECDSA(intermediate_ca_cert.signature_hash_algorithm),
        )
        print("✅ Intermediate CA is trusted by the Root CA.")
        print("✅ Full certificate chain is valid!")

        print("\n⚠️ SKIPPING final signature validation of VICAL data.")

        decoded_records = cbor2.loads(payload_with_certs)
        final_records_list = decoded_records.get('certificateInfos')
        extract_and_save_iacas(final_records_list)

    except InvalidSignature as e:
        print(f"❌ Certificate chain validation FAILED. Reason: {e}")
    except Exception as e:
        print(f"❌ An unexpected error occurred during processing: {e}")

def extract_and_save_iacas(issuer_records):
    """Extracts Issuer Authority Certificates and renames them based on a defined map."""
    if issuer_records is None:
        print("❌ Could not find the list of certificates in the payload. Halting extraction.")
        return
        
    if not os.path.exists(OUTPUT_CERT_DIR):
        os.makedirs(OUTPUT_CERT_DIR)

    # --- Renaming map for specific certificates TODO: make filenaming dynamic based on the state reflected in the certificate metadata---
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
    # ----------------------------------------------------
    print(f"\nFound {len(issuer_records)} issuer certificates. Extracting and renaming...")
    for record in issuer_records:
        cert_der = record.get('certificate') or record.get('iaca')
        if not cert_der:
            print("  -> ⚠️ Could not find certificate bytes in a record. Skipping.")
            continue
        try:
            cert = x509.load_der_x509_certificate(cert_der)
            subject = cert.subject.rfc4514_string()
            cn_attr = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)

            # Generate the original, safe filename
            filename_safe = ''.join(e for e in cn_attr[0].value if e.isalnum() or e in (' ','-')).replace(' ', '_')
            original_filename = f"{filename_safe.lower()}.pem" if cn_attr else 'unknown_issuer.pem'

            # Check the map and apply the new name if it exists
            final_filename = rename_map.get(original_filename, original_filename)

            # --- NEW: File Serialization Logic ---
            output_path = os.path.join(OUTPUT_CERT_DIR, final_filename)
            counter = 1
            # Loop while the file path already exists
            while os.path.exists(output_path):
                # Create a new name with a prefix and update the path
                new_filename = f"{counter}_{final_filename}"
                output_path = os.path.join(OUTPUT_CERT_DIR, new_filename)
                counter += 1
            # ------------------------------------

            pem_cert = cert.public_bytes(encoding=serialization.Encoding.PEM)

            with open(output_path, 'wb') as f:
                f.write(pem_cert)

            # Get the final actual filename from the full path
            actual_filename = os.path.basename(output_path)
            rename_notice = f" (renamed from {original_filename})" if actual_filename != original_filename else ""

            print(f"  -> ✅ Extracted and saved '{subject}' to {output_path}{rename_notice}")

        except Exception as e:
            print(f"  -> ❌ Failed to process a certificate record: {e}")

# --- UPDATED: Main Execution Block ---
if __name__ == "__main__":
    print("--- VICAL Decoding and Extraction Script ---")
    
    # Create a temporary directory to store downloaded files
    temp_dir = tempfile.mkdtemp()
    print(f"\nCreated temporary directory: {temp_dir}")
    
    try:
        # Define file paths within the temporary directory
        root_ca_path = os.path.join(temp_dir, 'ca_root.crt')
        intermediate_ca_path = os.path.join(temp_dir, 'ca_intermediate.crt')
        vsc_path = os.path.join(temp_dir, 'vicalsigner.crt')
        vical_path = os.path.join(temp_dir, 'aamva_vical.cbor')
        
        # Download all required files
        if not all([
            download_file(URL_ROOT_CA, root_ca_path),
            download_file(URL_INTERMEDIATE_CA, intermediate_ca_path),
            download_file(URL_VICAL_SIGNER, vsc_path),
            download_file(URL_VICAL_FILE, vical_path)
        ]):
            print("\n❌ Halting script due to download failure.")
            exit(1)

        print("\n--- Starting Processing ---")
        
        # Load all certificates from their temporary paths
        root_ca_cert = load_cert_from_pem(root_ca_path)
        intermediate_ca_cert = load_cert_from_pem(intermediate_ca_path)
        vsc_cert = load_cert_from_pem(vsc_path)
        
        if not root_ca_cert or not intermediate_ca_cert or not vsc_cert:
            exit(1)

        print(f"✅ DTS Root CA loaded: {root_ca_cert.subject.rfc4514_string()}")
        print(f"✅ DTS Intermediate CA loaded: {intermediate_ca_cert.subject.rfc4514_string()}")
        print(f"✅ VICAL Signer Certificate loaded: {vsc_cert.subject.rfc4514_string()}")

        vical_data = load_vical_file(vical_path)
        if not vical_data:
            exit(1)
        print("✅ VICAL CBOR file successfully parsed.")

        # Pass all necessary certs to the processing function
        process_vical(vical_data, root_ca_cert, intermediate_ca_cert, vsc_cert)
    
    finally:
        # Clean up the temporary directory and its contents
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
            print(f"\n✅ Cleaned up temporary directory: {temp_dir}")
            
    print("\n--- Script finished. ---")
