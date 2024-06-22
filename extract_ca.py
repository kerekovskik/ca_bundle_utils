import argparse
import socket
import ssl
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import logging
import certifi
from OpenSSL import SSL, crypto

logging.basicConfig(level=logging.INFO)

def get_cert_chain(hostname, port=443):
    context = SSL.Context(SSL.SSLv23_METHOD)
    context.set_verify(SSL.VERIFY_NONE, lambda *args: True)

    conn = SSL.Connection(context, socket.socket(socket.AF_INET, socket.SOCK_STREAM))
    conn.set_tlsext_host_name(hostname.encode())
    conn.connect((hostname, port))
    conn.do_handshake()

    cert_chain = conn.get_peer_cert_chain()
    conn.close()

    pem_chain = []
    for cert in cert_chain:
        pem_data = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
        pem_chain.append(pem_data.decode('utf-8'))

    return pem_chain

def load_certs_from_pem(pem_data):
    certs = []
    current_cert = []
    for line in pem_data.splitlines():
        if line.startswith('-----BEGIN CERTIFICATE-----'):
            current_cert = [line]
        elif line.startswith('-----END CERTIFICATE-----'):
            current_cert.append(line)
            cert_pem = '\n'.join(current_cert)
            cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
            certs.append(cert)
            current_cert = []
        elif current_cert:
            current_cert.append(line)
    return certs

def build_ca_chain(server_certs, system_certs, user_ca_bundle=None):
    ca_chain = []
    cert_sources = {}
    
    # Add server certs (excluding the first one, which is the server's own cert)
    for cert in server_certs[1:]:
        if cert not in ca_chain:
            ca_chain.append(cert)
            cert_sources[cert] = "Server Chain"

    current_cert = server_certs[-1]  # Start with the last cert from the server

    while True:
        # If we've reached a self-signed certificate, we're done
        if current_cert.issuer == current_cert.subject:
            break

        # Find the issuer in the system certs or user CA bundle
        issuer_cert = None
        for cert in system_certs:
            if cert.subject == current_cert.issuer:
                issuer_cert = cert
                source = "System CA Certs"
                break
        
        if not issuer_cert and user_ca_bundle:
            for cert in user_ca_bundle:
                if cert.subject == current_cert.issuer:
                    issuer_cert = cert
                    source = "User CA Bundle"
                    break

        if not issuer_cert:
            print(f"Warning: Could not find issuer for {current_cert.subject}")
            break

        if issuer_cert not in ca_chain:
            ca_chain.append(issuer_cert)
            cert_sources[issuer_cert] = source

        current_cert = issuer_cert

    return ca_chain, cert_sources

def save_cert_bundle(certs, filename):
    with open(filename, 'wb') as f:
        for cert in certs:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

def main():
    parser = argparse.ArgumentParser(description="Extract CA certificate chain for a hostname")
    parser.add_argument("--host", required=True, help="Hostname to connect to")
    parser.add_argument("--port", type=int, default=443, help="Port to connect to")
    parser.add_argument("--output", required=True, help="Output filename for the CA certificate bundle (PEM format)")
    parser.add_argument("--ca-bundle", help="Path to a user-provided CA bundle file")
    args = parser.parse_args()

    try:
        # Get server certificates
        server_cert_pems = get_cert_chain(args.host, args.port)
        server_certs = [load_certs_from_pem(pem)[0] for pem in server_cert_pems]
        print(f"Loaded {len(server_certs)} certificates from server")

        # Load system certificates using certifi
        with open(certifi.where(), 'rb') as f:
            cert_data = f.read()
            system_certs = load_certs_from_pem(cert_data.decode())
        print(f"Loaded {len(system_certs)} system certificates")

        # Load user-provided CA bundle if specified
        user_ca_bundle = None
        if args.ca_bundle:
            with open(args.ca_bundle, 'rb') as f:
                user_ca_bundle = load_certs_from_pem(f.read().decode())
            print(f"Loaded {len(user_ca_bundle)} certificates from user-provided CA bundle")

        # Build the CA chain
        ca_chain, cert_sources = build_ca_chain(server_certs, system_certs, user_ca_bundle)

        if ca_chain:
            save_cert_bundle(ca_chain, args.output)
            print(f"\nCA certificate chain saved to {args.output}")
            print(f"Number of certificates in the chain: {len(ca_chain)}")
            for i, cert in enumerate(ca_chain, 1):
                print(f"\nCertificate {i}:")
                print(f"  Subject: {cert.subject}")
                print(f"  Issuer: {cert.issuer}")
                print(f"  Source: {cert_sources[cert]}")
        else:
            print("No CA certificates found in the chain.")

    except Exception as e:
        print(f"Error: {str(e)}")
        import traceback
        print(traceback.format_exc())

if __name__ == "__main__":
    main()