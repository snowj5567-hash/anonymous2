import hashlib
import sys
import json
try:
    import ssdeep
    SSDEEP_AVAILABLE = True
except ImportError:
    SSDEEP_AVAILABLE = False

def calculate_hashes(file_path):
    """
    Calculates various cryptographic hashes for a given file.
    """
    hashes = {}
    try:
        with open(file_path, 'rb') as f:
            file_data = f.read()
            hashes['md5'] = hashlib.md5(file_data).hexdigest()
            hashes['sha1'] = hashlib.sha1(file_data).hexdigest()
            hashes['sha256'] = hashlib.sha256(file_data).hexdigest()
            if SSDEEP_AVAILABLE:
                try: 
                    hashes['ssdeep'] = ssdeep.hash(file_data)
                except Exception as e: 
                    hashes['ssdeep'] = f"Error: {e}"
            else: 
                hashes['ssdeep'] = "N/A (library not available)"
    except Exception as e: 
        return {"error": f"Hash read error: {e}"}
    return hashes

    
if __name__ == "__main__":
    result = calculate_hashes(sys.argv[1])
    print(json.dumps(result))