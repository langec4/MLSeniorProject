import streamlit as st
import pandas as pd
import joblib  
import pefile
import numpy as np
import os

# Loads the pre-trained model
model = joblib.load('/Users/carterlange/Desktop/ML-Senior-Project/MLProject.pkl')

# Features list, from our dataset
EXPECTED_FEATURES = [
    'AddressOfEntryPoint', 'MajorLinkerVersion', 'MajorImageVersion',
    'MajorOperatingSystemVersion', 'DllCharacteristics', 'SizeOfStackReserve',
    'NumberOfSections', 'ResourceSize', 'Entropy', 'ImportCount', 'Packed', 'Timestamp'
]

# Function to ensure the extracted features match the expected format
def ensure_feature_consistency(features):
    consistent_features = pd.DataFrame(columns=EXPECTED_FEATURES)
    
    for feature in EXPECTED_FEATURES:
        if feature in features.columns:
            consistent_features[feature] = features[feature]
        else:
            consistent_features[feature] = 0  # if given feature has no value, sets it to 0
    
    return consistent_features[EXPECTED_FEATURES]

# Helper function to calculate entropy for each section
def calculate_entropy(data):
    if len(data) == 0:
        return 0.0
    entropy = 0
    for x in range(256):
        p_x = data.count(chr(x)) / len(data)
        if p_x > 0:
            entropy += - p_x * np.log2(p_x)
    return entropy

# Extract features for an EXE file
def extract_features_from_exe(uploaded_file):
    try:
        pe = pefile.PE(data=uploaded_file.read())
        
        # Extracts primary features (same as features in dataset)
        features = pd.DataFrame([[
            pe.OPTIONAL_HEADER.AddressOfEntryPoint, 
            pe.OPTIONAL_HEADER.MajorLinkerVersion, 
            pe.OPTIONAL_HEADER.MajorImageVersion, 
            pe.OPTIONAL_HEADER.MajorOperatingSystemVersion, 
            pe.OPTIONAL_HEADER.DllCharacteristics, 
            pe.OPTIONAL_HEADER.SizeOfStackReserve, 
            len(pe.sections), 
            pe.OPTIONAL_HEADER.SizeOfInitializedData,
           
            np.mean([calculate_entropy(str(section.get_data())) for section in pe.sections]),  # Entropy
            len(pe.DIRECTORY_ENTRY_IMPORT) if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT') else 0,    # Import Count
            int(np.mean([calculate_entropy(str(section.get_data())) for section in pe.sections]) > 7),  # Packed flag
            pe.FILE_HEADER.TimeDateStamp if hasattr(pe.FILE_HEADER, 'TimeDateStamp') else 0  # Timestamp
        ]], columns=EXPECTED_FEATURES)
        
        # Ensure feature order and consistency
        return ensure_feature_consistency(features)
    
    except pefile.PEFormatError as e:
        st.warning(f"PEFormatError occurred with pefile: {e}.")
        return pd.DataFrame(columns=EXPECTED_FEATURES)
    
    except Exception as e:
        st.error(f"Unexpected error occurred: {e}")
        return pd.DataFrame(columns=EXPECTED_FEATURES)

# Extract features function
def extract_features(uploaded_file):
    filename = uploaded_file.name.lower()
    
    if filename.endswith('.exe'):
        return extract_features_from_exe(uploaded_file)  # This only returns for exe
    else:
        raise ValueError(f"Unsupported file type: {filename}. Supported types are: .exe")

# Streamlit Design
st.title("Malware Analysis Tool")
st.write("Upload a file (EXE) to check if it's malicious or safe.")

# File uploader for exe files
files = st.file_uploader("Upload a file to check for malwares:", accept_multiple_files=True, type=['exe'])

# threshold for malicious classification
THRESHOLD = 0.2

if files:
    with st.spinner("Checking..."):
        for uploaded_file in files:
            try:
                # Extract features from the EXE file
                features = extract_features(uploaded_file)
                
                if features.empty:
                    st.error(f"No valid features were extracted from {uploaded_file.name}. Please upload a valid EXE file.")
                else:
                    # Display the extracted features for debugging
                    st.write(f"Extracted features for {uploaded_file.name}:", features)

                    # Get the probability of each class (0 for safe, 1 for malicious)
                    probabilities = model.predict_proba(features)
                    
                    # Check if the probability of being malicious (class 1) is above the threshold
                    is_malicious = probabilities[0][1] >= THRESHOLD

                    # Output result based on thresholded 
                    if is_malicious:
                        st.markdown(f"**{uploaded_file.name}** is probably **Malicious**!!!")
                    else:
                        st.write(f"File **{uploaded_file.name}** seems *Safe*!")
            except Exception as e:
                st.error(f"An error occurred while processing {uploaded_file.name}: {e}")












