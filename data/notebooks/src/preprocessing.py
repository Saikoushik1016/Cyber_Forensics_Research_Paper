"""
Data preprocessing and feature engineering for AWS CloudTrail logs.
This module handles loading, cleaning, and feature engineering for the dataset.
"""
import pandas as pd
import numpy as np

# Expected columns from the dataset
EXPECTED_COLS = [
    "eventID", "eventTime", "sourceIPAddress", "userAgent", "eventName", 
    "eventSource", "awsRegion", "eventVersion", "userIdentitytype", 
    "eventType", "requestID", "userIdentityaccountId", "userIdentityprincipalId",
    "userIdentityarn", "userIdentityaccessKeyId", "userIdentityuserName", 
    "errorCode", "errorMessage", "requestParametersinstanceType"
]

def load_dataset(path: str) -> pd.DataFrame:
    """
    Load the CloudTrail dataset (CSV). Attempts to parse eventTime as datetime.
    
    Args:
        path: Path to the CSV file
        
    Returns:
        DataFrame with loaded data
    """
    try:
        df = pd.read_csv(path, low_memory=False)
    except Exception:
        # Fallback if encoding issues
        df = pd.read_csv(path, encoding_errors='ignore', low_memory=False)
    
    # Parse timestamps if present
    if "eventTime" in df.columns:
        df["eventTime"] = pd.to_datetime(df["eventTime"], errors="coerce")
    
    return df

def add_time_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Add time-derived features so rules and models can use temporal context.
    
    Args:
        df: Input DataFrame with eventTime column
        
    Returns:
        DataFrame with added time features (eventHour, eventDay, eventDow)
    """
    if "eventTime" in df.columns:
        df["eventHour"] = df["eventTime"].dt.hour
        df["eventDay"] = df["eventTime"].dt.day
        df["eventDow"] = df["eventTime"].dt.dayofweek
    else:
        # If missing, fill sentinel values
        df["eventHour"] = -1
        df["eventDay"] = -1
        df["eventDow"] = -1
    return df

def ensure_output_columns(df: pd.DataFrame) -> pd.DataFrame:
    """
    Create the two new output columns required by TA (if not already present).
    
    Args:
        df: Input DataFrame
        
    Returns:
        DataFrame with Is_Malicious and Malicious_Type columns
    """
    if "Is_Malicious" not in df.columns:
        df["Is_Malicious"] = 0  # 0 = legit, 1 = malicious
    if "Malicious_Type" not in df.columns:
        df["Malicious_Type"] = ""  # string label for malicious category
    return df

# Example usage
if __name__ == "__main__":
    # Load and preprocess dataset
    df = load_dataset('data/dec12_18features.csv')
    df = add_time_features(df)
    df = ensure_output_columns(df)
    
    print(f"Loaded {len(df):,} records with {len(df.columns)} columns")
    print(f"\nFirst few rows:")
    print(df.head())
    print(f"\nDataset info:")
    print(df.info())
