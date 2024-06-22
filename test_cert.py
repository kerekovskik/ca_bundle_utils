import ssl
import socket
from datetime import datetime
import datetime as dt
import concurrent.futures
import cryptography
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import argparse
import os
import certifi
import fnmatch

def create_ssl_context(ca_bundle=None):
    if ca_bundle:
        context = ssl.create_default_context(cafile=ca_bundle)
    else:
        context = ssl.create_default_context(cafile=certifi.where())
    return context

def hostname_matches(hostname, cert_hostname):
    """Check if hostname matches cert_hostname, considering wildcards."""
    return fnmatch.fnmatch(hostname, cert_hostname)

def get_issuer_info(cert):
    """Extract issuer information from the certificate."""
    issuer = cert.issuer
    common_name = next((attr.value for attr in issuer if attr.oid == x509.oid.NameOID.COMMON_NAME), None)
    organization = next((attr.value for attr in issuer if attr.oid == x509.oid.NameOID.ORGANIZATION_NAME), None)
    return f"{common_name} ({organization})" if organization else common_name


def check_cert(hostname, ca_bundle=None):
    try:
        context = create_ssl_context(ca_bundle)
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED

        with socket.create_connection((hostname, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as secure_sock:
                der_cert = secure_sock.getpeercert(binary_form=True)
                cert = x509.load_der_x509_certificate(der_cert, default_backend())
                cert_dict = secure_sock.getpeercert()
                
                issues = []
                
                # Check expiration
                current_time_utc = datetime.now(dt.timezone.utc)
                
                if cert.not_valid_after_utc < current_time_utc:
                    issues.append(f"Certificate expired on {cert.not_valid_after_utc}")
                elif (cert.not_valid_after_utc - current_time_utc).days < 30:
                    issues.append(f"Certificate will expire soon on {cert.not_valid_after_utc}")
                
                # Check hostname and collect all hostnames in the cert
                cert_hostnames = set()
                cert_hostnames.update(value for key, value in dict(cert_dict['subject'][0]).items() if key == 'commonName')
                cert_hostnames.update(san[1] for san in cert_dict.get('subjectAltName', []) if san[0] == 'DNS')
                
                # Enhanced hostname check with wildcard support
                matching_hostnames = [ch for ch in cert_hostnames if hostname_matches(hostname, ch)]
                if not matching_hostnames:
                    issues.append(f"Hostname mismatch. Checked: {hostname}, In cert: {', '.join(cert_hostnames)}")
                
                # Check if self-signed
                if cert.issuer == cert.subject:
                    issues.append("Certificate is self-signed")
                
                # Check weak signature algorithm
                if cert.signature_algorithm_oid._name in ['md5WithRSAEncryption', 'sha1WithRSAEncryption']:
                    issues.append(f"Weak signature algorithm: {cert.signature_algorithm_oid._name}")
                
                # Check key size
                public_key = cert.public_key()
                key_size = public_key.key_size
                if isinstance(public_key, cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey) and key_size < 2048:
                    issues.append(f"Weak RSA key size: {key_size} bits")
                elif isinstance(public_key, cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey) and key_size < 224:
                    issues.append(f"Weak ECC key size: {key_size} bits")
                
                # Check for Basic Constraints extension (CA:TRUE)
                try:
                    basic_constraints = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.BASIC_CONSTRAINTS)
                    if basic_constraints.value.ca:
                        issues.append("Certificate can act as a CA (Basic Constraints: CA:TRUE)")
                except x509.extensions.ExtensionNotFound:
                    pass  # Basic Constraints extension not present, which is fine for end-entity certs
                
                # Get root CA info
                root_ca_info = get_issuer_info(cert)
                
                if not issues:
                    return hostname, None, root_ca_info
                else:
                    return hostname, issues, None

    except ssl.SSLCertVerificationError as e:
        return hostname, [f"SSL Certificate Verification Error: {str(e)}"], None
    except ssl.SSLError as e:
        return hostname, [f"SSL Error: {str(e)}"], None
    except socket.error as e:
        return hostname, [f"Socket Error: {str(e)}"], None
    except Exception as e:
        return hostname, [f"Unexpected Error: {str(e)}"], None
  
def check_multiple_hosts(hosts, ca_bundle=None):
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        results = executor.map(lambda host: check_cert(host, ca_bundle), hosts)
    return results

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Comprehensive SSL Certificate Checker with CA Trust Information")
    parser.add_argument("hosts", nargs="+", help="Hostnames to check")
    parser.add_argument("--ca-bundle", help="Path to custom CA bundle PEM file")
    args = parser.parse_args()

    ca_bundle = args.ca_bundle or os.environ.get('SSL_CERT_FILE')

    results = check_multiple_hosts(args.hosts, ca_bundle)
    
    for hostname, issues, root_ca_info in results:
        if issues:
            print(f"{hostname}:")
            for issue in issues:
                print(f"  - {issue}")
        else:
            print(f"{hostname}: No issues detected")
            if root_ca_info:
                print(f"  Trusted by: {root_ca_info}")
        print()  # Add a blank line between results for better readability