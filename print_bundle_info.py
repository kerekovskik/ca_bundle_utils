import argparse
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
import datetime

def load_certs_from_pem(filename):
    with open(filename, 'rb') as f:
        cert_data = f.read()
    certs = []
    for cert_bytes in cert_data.split(b'-----BEGIN CERTIFICATE-----')[1:]:
        cert_bytes = b'-----BEGIN CERTIFICATE-----' + cert_bytes
        cert = x509.load_pem_x509_certificate(cert_bytes, default_backend())
        certs.append(cert)
    return certs

def get_name_string(name):
    """Convert a cryptography.x509.Name object to a string."""
    return ', '.join([f"{attr.oid._name}={attr.value}" for attr in name])

def print_cert_info(cert, index):
    print(f"\nCertificate {index}:")
    print("=" * 20)
    print(f"Version: {cert.version}")
    print(f"Serial Number: {cert.serial_number}")
    print(f"Subject: {get_name_string(cert.subject)}")
    print(f"Issuer: {get_name_string(cert.issuer)}")
    print(f"Not Valid Before: {cert.not_valid_before_utc}")
    print(f"Not Valid After: {cert.not_valid_after_utc}")
    
    # Public Key Information
    public_key = cert.public_key()
    print(f"Public Key Algorithm: {public_key.__class__.__name__}")
    if hasattr(public_key, 'key_size'):
        print(f"Key Size: {public_key.key_size} bits")
    
    # Extensions
    print("Extensions:")
    for extension in cert.extensions:
        print(f"  {extension.oid._name}:")
        if isinstance(extension.value, x509.BasicConstraints):
            print(f"    CA: {extension.value.ca}")
            if extension.value.ca and extension.value.path_length is not None:
                print(f"    Path Length Constraint: {extension.value.path_length}")
        elif isinstance(extension.value, x509.SubjectAlternativeName):
            print("    Subject Alternative Names:")
            for name in extension.value:
                print(f"      {name}")
        else:
            print(f"    {extension.value}")

def main():
    parser = argparse.ArgumentParser(description="Display information for multiple certificates from a PEM file")
    parser.add_argument("pem_file", help="Path to the PEM file containing the certificate(s)")
    args = parser.parse_args()

    try:
        certs = load_certs_from_pem(args.pem_file)
        print(f"Found {len(certs)} certificate(s) in the PEM file.")
        for i, cert in enumerate(certs, 1):
            print_cert_info(cert, i)
    except Exception as e:
        print(f"Error: {str(e)}")

if __name__ == "__main__":
    main()