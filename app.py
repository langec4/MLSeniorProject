import streamlit as st
import pandas as pd
import joblib  
import os


# Load your trained model
model = joblib.load('/Users/carterlange/Desktop/ML-Senior-Project/MLProject.pkl')

# Function to predict if the file is malicious or safe
def predict(file):
    # Extract features from the file
    features = extract_features(file)
    # Use the model to make a prediction
    prediction = model.predict(features)
    return prediction

def extract_features(uploaded_file):
    # Read the uploaded CSV file into a DataFrame
    df = pd.read_csv(uploaded_file)

    # Check if the 'legitimate' column exists
    if 'legitimate' in df.columns:
        features = df[['legitimate']]  # Extract the 'legitimate' feature
        return features
    else:
        raise ValueError("The 'legitimate' column is not present in the dataset.")

# Streamlit app layout
st.title("Malware Analysis Tool")
st.write("Upload a CSV file to check if it's malicious or safe.")

# File uploader
# File uploader with multiple file types
uploaded_file = st.file_uploader("Choose a file", type=['csv', 'exe', 'dll', 'py', 'jar', 'zip'])


if uploaded_file is not None:
    # Call your prediction function
    try:
        prediction = predict(uploaded_file)
        
        # Display the result
        if prediction[0] == 1:  # Adjust based on your model's output
            st.write("The file is **malicious**.")
        else:
            st.write("The file is **safe**.")
    except Exception as e:
        st.error(f"An error occurred: {e}")

