# Welcome to our Senior Project!

A simple Streamlit app template for you to modify!

[![Open in Streamlit](https://static.streamlit.io/badges/streamlit_badge_black_white.svg)](https://blank-app-template.streamlit.app/)

## How to run it on your own machine ##

1. Install the requirements

   ```
   $ pip install -r requirements.txt
   ```

2. Run the app

   ```
   $ Local URL: http://localhost:8502
     Network URL: http://192.168.4.23:8502
   (This is not working/implemented yet)
   ```

## Our dataset we used ##
   ```
   $ Malware Dataset: https://github.com/emr4h/Malware-Detection-Using-Machine-Learning/tree/main/data-set
   Below are the features that are present in this dataset
   ```
   Address Point Of Entry: Refers to a specific address in memory where the execution of a malicious program starts. Most malicious files use same    entry points, so this could help in identifying malware vs legit files as legit files have different entry points as a whole.
 
Major Linker Version: Refers to specific version of a linker that compiles the source code of an execuatble and links them to a library so that they can be executed. Malicious files may use specific linkers or (techniques of linking to libraries or other executables).
 
Major Image Version: Refers to the compiled binary file of the malware as malware may have specific compiled patterns compared to legit files.
 
Major Operating System Version: Refers to the OS version that is required to run the malware. Some OS may be targeted more than others, especially when downloading malware.
 
DLL Characteristics: Refers to Dynamic Link Libraries used when executing a file (malware). Could show how executable interacts in a malicious or legit way (if they interact with security features and try to access permissions).
 
Size of Stack Reserve: Refers to how many stack frames are reserved for executable file. Malicious files could try to reserve very large stack frames for different attack staregies.
 
Number Of Sections.data: Refers to sections of different parts program has when linker compiles files into final version of executable. Malicious files may have large data amounts in various sections. These sections may be encoded, obfruscated, etc... to make them harder to detect. Larger sections may indicate more malicious behavior.
 
Resource Size: Refers to resouces used by executable (strings, images, icons, calls to outside sources). Malicious files may use similar icons, images, calls, etc... which could be used to compare to legit resource sizes that do not have these things in them.
 
Legitimate Data: Either 0 legit, or 1 malicious (labels associated with distinguishing in our dataset).
has context menu

All of these features are used for training the model with the dataset. Then, these same features are extracted with their values when you upload a given executable file to the streamlit.

The legitimate column has values 0 or 1, with 0 = safe and 1 = malicious. This column is needed for training, so based on the other values, it will learn what makes a file safe vs malicious






## Random Forest Algorithm ##
   Uses labeled training data to help the system recognize patterns and predict outcomes accurately. After making the decision trees, each individual tree comes to a single decision (safe or malicious), and uses voting (majority rules) to give us a final result.

## Decision Trees ## 
   A map of the possible outcomes of a series of related choices. Our project uses 50 decision trees. After using gridsearch, it told us to use 50 decision trees. Also, when doing research on the topic earlier this semester, their were a lot of reccomendations to use 50 trees.

## Gradient Boosting ##
   Gradient boosting is a machine learning technique that takes weaker models and combines them to make one strong model. 

## Grid Search/Random Search ##
   Grid search is a method that finds the best possible combination of hyperparameters with their values to provide us with the best accuracy/score


## Pefile Python Library ##

   This library is used in our app.py, which extracts the values of the features with the file you uploaded. This is then displayed on our streamlit website. This library is used to parse and work with Portable Executable files (PE).
   https://github.com/erocarrera/pefile (This is the link for the official documentation of pefile)
   https://pefile.readthedocs.io/en/latest/modules/pefile.html
   


