"""
Rule-based labeling for AWS CloudTrail malicious activity detection.
Implements 12 security rules in strict order (first-match wins).
"""
import pandas as pd
import ipaddress
import re

def is_public_ip(ip):
    """Check if IP address is public (not private/loopback)."""
    try:
        ip = str(ip)
        ip_obj = ipaddress.ip_address(ip)
        return not (ip_obj.is_private or ip_obj.is_loopback)
    except Exception:
        return False

def normalize_field(val):
    """Normalize common text fields to lowercase, safe string."""
    try:
        if pd.isnull(val):
            return ""
        return str(val).strip().lower()
    except Exception:
        return ""

def check_s3_policy_public(rp):
    """
    Check for Principal:"*", Action:"s3:*", Resource:"*"
    """
    if not isinstance(rp, str):
        return False
    rp_lower = rp.lower()
    return ('principal":"*"' in rp_lower or 
            ('action":"s3:*"' in rp_lower and 'resource":"*"' in rp_lower))

def check_console_status(val):
    """Extract console login status."""
    try:
        if pd.isnull(val):
            return ""
        return str(val).strip().lower()
    except Exception:
        return ""

def apply_rules(row):
    """
    Apply security rules to a single event record.
    Returns pandas Series with [Is_Malicious, Malicious_Type].
    """
    # Extract all normalized values first
    eventName = normalize_field(row.get('eventName', ''))
    eventSource = normalize_field(row.get('eventSource', ''))
    userAgent = normalize_field(row.get('userAgent', ''))
    errorCode = normalize_field(row.get('errorCode', ''))
    userType = normalize_field(row.get('userIdentitytype', ''))
    sourceIPAddress = normalize_field(row.get('sourceIPAddress', ''))
    reqParams = normalize_field(row.get('requestParameters', ''))
    
    # For console login status, try multiple keys
    console_status = ""
    if 'responseElements.ConsoleLogin' in row:
        console_status = normalize_field(row['responseElements.ConsoleLogin'])
    elif 'ConsoleLogin' in row:
        console_status = normalize_field(row['ConsoleLogin'])
    elif 'responseElements' in row and isinstance(row['responseElements'], dict):
        console_status = normalize_field(row['responseElements'].get('ConsoleLogin', ''))

    is_public = is_public_ip(sourceIPAddress)
    s3_policy_public = check_s3_policy_public(reqParams)
    
    # ---------- Rules in strict order (first-match wins) ----------
    
    # R1 — credential_access
    if eventName == "getsecretvalue" or (eventSource == "kms.amazonaws.com" and eventName == "decrypt"):
        return pd.Series([1, "credential_access"])
    
    # R2 — brute_force_attempt
    elif eventName == "consolelogin" and console_status == "failure":
        return pd.Series([1, "brute_force_attempt"])
    
    # R3 — cloudtrail_disruption
    elif eventSource == "cloudtrail.amazonaws.com" and eventName in ["stoplogging", "deletetrail", "updatetrail"]:
        return pd.Series([1, "cloudtrail_disruption"])
    
    # R4 — defense_evasion_logging_disable (non-CloudTrail)
    elif eventSource == "guardduty.amazonaws.com" and eventName in [
        "deletedetector","deletemembers","disassociatemembers","stopmonitoringmembers"]:
        return pd.Series([1, "defense_evasion_logging_disable"])
    
    # R5 — privilege_escalation (IAM write/priv ops)
    elif eventSource == "iam.amazonaws.com" and eventName in [
        "createrole","attachrolepolicy","addroletoinstanceprofile",
        "createinstanceprofile","passrole","putrolepolicy","updateassumerolepolicy"]:
        return pd.Series([1, "privilege_escalation"])
    
    # R6 — reconnaissance_enumeration (from public IP)
    elif (eventName.startswith("describe") or eventName.startswith("list")) and is_public:
        return pd.Series([1, "reconnaissance_enumeration"])
    
    # R7 — s3_policy_tampering
    elif eventSource == "s3.amazonaws.com" and eventName == "putbucketpolicy" and s3_policy_public:
        return pd.Series([1, "s3_policy_tampering"])
    
    # R8 — unauthorized_access_attempt (generic failures)
    elif errorCode in ["accessdenied","unauthorizedoperation","nosuchentityexception"]:
        return pd.Series([1, "unauthorized_access_attempt"])
    
    # R9 — exfiltration_suspected (successful S3 data ops from public IP)
    elif eventName in ["getobject","listbuckets","getbucketacl"] and is_public and errorCode in ["", None]:
        return pd.Series([1, "exfiltration_suspected"])
    
    # R10 — persistence_access_key_creation
    elif eventName == "createaccesskey" and userType == "iamuser":
        return pd.Series([1, "persistence_access_key_creation"])
    
    # R11 — suspicious_tool_useragent
    elif any(tool in userAgent for tool in ["kali","parrot","powershell"]):
        return pd.Series([1, "suspicious_tool_useragent"])
    
    # R12 — legit (default)
    else:
        return pd.Series([0, "legit"])

def label_dataset(df: pd.DataFrame) -> pd.DataFrame:
    """
    Apply rules to entire dataset.
    
    Args:
        df: Input DataFrame with CloudTrail events
        
    Returns:
        DataFrame with Is_Malicious and Malicious_Type columns populated
    """
    df[["Is_Malicious", "Malicious_Type"]] = df.apply(apply_rules, axis=1)
    return df

# Example usage
if __name__ == "__main__":
    import preprocessing
    
    # Load and preprocess
    df = preprocessing.load_dataset('data/dec12_18features.csv')
    df = preprocessing.add_time_features(df)
    df = preprocessing.ensure_output_columns(df)
    
    # Apply rule-based labeling
    df = label_dataset(df)
    
    print(f"Labeled {len(df):,} records")
    print(f"\nMalicious_Type distribution:")
    print(df["Malicious_Type"].value_counts())
    print(f"\nIs_Malicious distribution:")
    print(df["Is_Malicious"].value_counts())
