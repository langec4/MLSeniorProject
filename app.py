import streamlit as st
import pandas as pd
import joblib  
import pefile
import numpy as np
import os

# Load the pre-trained model
model = joblib.load('/Users/carterlange/Desktop/ML-Senior-Project/MLProject.pkl')

# Define the expected features list, including new features
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
            consistent_features[feature] = 0  # Default for missing features
    
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
        
        # Extract primary features and add the new ones
        features = pd.DataFrame([[
            pe.OPTIONAL_HEADER.AddressOfEntryPoint, 
            pe.OPTIONAL_HEADER.MajorLinkerVersion, 
            pe.OPTIONAL_HEADER.MajorImageVersion, 
            pe.OPTIONAL_HEADER.MajorOperatingSystemVersion, 
            pe.OPTIONAL_HEADER.DllCharacteristics, 
            pe.OPTIONAL_HEADER.SizeOfStackReserve, 
            len(pe.sections), 
            pe.OPTIONAL_HEADER.SizeOfInitializedData,
            # New features
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

# General function to extract features based on file type
def extract_features(uploaded_file):
    filename = uploaded_file.name.lower()
    
    if filename.endswith('.exe'):
        return extract_features_from_exe(uploaded_file)  # Only return features for EXE
    else:
        raise ValueError(f"Unsupported file type: {filename}. Supported types are: .exe")

# Streamlit app layout
st.title("Malware Analysis Tool")
st.write("Upload a file (EXE) to check if it's malicious or safe.")

# File uploader for multiple files
files = st.file_uploader("Upload a file to check for malwares:", accept_multiple_files=True, type=['exe'])

# Define a threshold for malicious classification
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

                    # Output result based on thresholded probability
                    if is_malicious:
                        st.markdown(f"**{uploaded_file.name}** is probably **Malicious**!!!")
                    else:
                        st.write(f"File **{uploaded_file.name}** seems *LEGITIMATE*!")
            except Exception as e:
                st.error(f"An error occurred while processing {uploaded_file.name}: {e}")





        
        
#For example, for .exe files, it reads metadata from the file's headers (using the pefile library).
# For .csv files, it reads features directly from the file’s columns (ignoring the legitimate column if present).
# .dll uses the pe header to extract features from the file headers
# .zip files use the pyzipper library to handle encrypted zip files. It gets the number of files within the zip archive
# for py files, we are extracting the length of the file content (aka num of bytes)


# PREDICTOR
# The features that are extracted are then passed to our pre trained ML Model
# which then predicts if the file is malicious or not (1 = malicious, 0 = safe)
# Each file in the dataset had similar features (similar to the ones we are extracting in our app)
# The model learned features through training, and associated each certain feature combination with either malicious or safe
# And when you upload a file to the streamlit, the extracted features from the file you upload is compared to 
# what the model learned from the training dataset
# During the training, the model learned what features are the most important in determining if a file is malicious or safe
# The app extracts the same features from the dataset and uses those to predict whether the file is safe or not
# The model then uses these features to compare the new file to the patterns it learned from the dataset, and makes a prediction.















