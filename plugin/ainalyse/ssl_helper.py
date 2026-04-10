import os
import re
import httpx


def create_openai_client_with_custom_ca(api_key: str, base_url: str, custom_ca_cert_path: str = "", client_cert_path: str = "", client_key_path: str = "", feature: str = "") -> 'OpenAI':
    """Create OpenAI client with disabled SSL verification and optional client certificates."""
    from openai import OpenAI
    
    httpx_client = None
    client_cert_key = None
    
    # Setup client certificate and key for mTLS
    if client_cert_path and client_key_path:
        try:
            # Verify both files exist
            if not os.path.exists(client_cert_path):
                raise FileNotFoundError(f"Client certificate file not found: {client_cert_path}")
            if not os.path.exists(client_key_path):
                raise FileNotFoundError(f"Client key file not found: {client_key_path}")
            
            client_cert_key = (client_cert_path, client_key_path)
            print(f"[AETHER] Using client certificate: {client_cert_path} with key: {client_key_path}")
        except FileNotFoundError as e:
            print(f"[AETHER] Warning: {e}. Proceeding without client certificate.")
            client_cert_key = None
        except Exception as e:
            print(f"[AETHER] Warning: Error setting up client certificate: {e}. Proceeding without client certificate.")
            client_cert_key = None
    elif client_cert_path or client_key_path:
        print("[AETHER] Warning: Both CLIENT_CERT_PATH and CLIENT_KEY_PATH must be provided for mTLS. Proceeding without client certificate.")

    # Create httpx client with SSL verification disabled
    try:
        if client_cert_key:
            httpx_client = httpx.Client(cert=client_cert_key, verify=False, timeout=600)
        else:
            httpx_client = httpx.Client(verify=False, timeout=600)
        print("[AETHER] SSL verification disabled for HTTPX client")
    except Exception as e:
        print(f"[AETHER] Warning: Error creating httpx client: {e}. Using basic client.")
        httpx_client = httpx.Client(verify=False, timeout=600)
    
    # Create User Agent
    custom_headers = {}
    
    version = get_version()
    if feature:
        custom_headers = { "User-Agent": f"AETHER (IDA)/alpha{version}-{feature}"}
    else:
        custom_headers = { "User-Agent": f"AETHER (IDA)/alpha{version}"}
    print(f"[AETHER] Added User-Agent header: {custom_headers['User-Agent']}")

    client = OpenAI(
        api_key=api_key,
        base_url=base_url,
        http_client=httpx_client,
        default_headers=custom_headers
    )
    return client

def get_version():
    base_dir = os.path.dirname(__file__)
    version_path = os.path.join(base_dir, "version.txt")
    try:
        with open(version_path, "r") as f:
            raw_content = f.read().strip()
        match = re.search(r'^[\d.]+', raw_content)
        return match.group(0) if match else "ErrVer"
    except FileNotFoundError:
        return "ErrVer"