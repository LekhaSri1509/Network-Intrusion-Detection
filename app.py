import streamlit as st
import pickle #LabelEncoder
import joblib #Scaler
import pandas as pd
scaler = joblib.load("C:\\Users\\Lenovo\\Documents\\streamlit\\machine learning\\datas\\robust_scaler (1).bin")
pkl_file = open("C:\\Users\\Lenovo\\Documents\\streamlit\\machine learning\\datas\\label_enc (2).pkl", 'rb')
encoder = pickle.load(pkl_file) 
pkl_file.close()
model = joblib.load("C:\\Users\\Lenovo\\Documents\\streamlit\\machine learning\\datas\\decmodel_jlib")

def highlight_survived(s):
    return ['background-color: green']*len(s) if s.Predicted=='Benign' else ['background-color: red']*len(s)

tot_lst = ['Dst Port', 'Flow Duration', 'Tot Fwd Pkts', 'Tot Bwd Pkts',
       'TotLen Fwd Pkts', 'TotLen Bwd Pkts', 'Fwd Pkt Len Max',
       'Fwd Pkt Len Min', 'Fwd Pkt Len Mean', 'Fwd Pkt Len Std',
       'Bwd Pkt Len Max', 'Bwd Pkt Len Min', 'Bwd Pkt Len Mean',
       'Bwd Pkt Len Std', 'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max',
       'Flow IAT Min', 'Fwd IAT Tot', 'Fwd IAT Mean', 'Fwd IAT Std',
       'Fwd IAT Max', 'Fwd IAT Min', 'Bwd IAT Tot', 'Bwd IAT Mean',
       'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags',
       'Bwd PSH Flags', 'Fwd URG Flags', 'Bwd URG Flags', 'Fwd Header Len',
       'Bwd Header Len', 'Fwd Pkts/s', 'Bwd Pkts/s', 'Pkt Len Min',
       'Pkt Len Max', 'Pkt Len Mean', 'Pkt Len Std', 'Pkt Len Var',
       'FIN Flag Cnt', 'SYN Flag Cnt', 'RST Flag Cnt', 'ACK Flag Cnt',
       'URG Flag Cnt', 'CWE Flag Count', 'ECE Flag Cnt', 'Pkt Size Avg',
       'Fwd Seg Size Avg', 'Bwd Seg Size Avg', 'Fwd Byts/b Avg',
       'Fwd Pkts/b Avg', 'Fwd Blk Rate Avg', 'Bwd Byts/b Avg',
       'Bwd Pkts/b Avg', 'Bwd Blk Rate Avg', 'Subflow Fwd Pkts',
       'Subflow Fwd Byts', 'Subflow Bwd Pkts', 'Subflow Bwd Byts',
       'Init Bwd Win Byts', 'Fwd Act Data Pkts', 'Fwd Seg Size Min',
       'Active Mean', 'Active Std', 'Active Max', 'Active Min', 'Idle Mean',
       'Idle Std', 'Idle Max', 'Idle Min']
lst = ['Unnamed: 0','Dst Port', 'TotLen Fwd Pkts', 'TotLen Bwd Pkts', 'Fwd Pkt Len Mean',
       'Bwd Pkt Len Mean', 'Fwd IAT Tot', 'Bwd IAT Tot', 'Bwd IAT Mean',
       'Fwd Pkts/s', 'Bwd Pkts/s', 'FIN Flag Cnt', 'SYN Flag Cnt',
       'RST Flag Cnt', 'ACK Flag Cnt', 'URG Flag Cnt', 'CWE Flag Count',
       'Init Bwd Win Byts', 'Active Mean', 'Idle Mean', 'Label']

menu=["Home","Analysis"]
choice=st.sidebar.selectbox("Menu",menu)
if(choice=="Home"):
    st.header("NETWORK INTRUSION DETECTION")
    st.markdown("<h2>Benign</h2><ul><li>Hello</li></ul>",unsafe_allow_html=True)
    st.markdown("<h2>Bot</h2><ul><li>A bot attack is the use of automated web requests to manipulate, defraud, or disrupt a website, application, API, or end-users</li></ul>",unsafe_allow_html=True)
    st.markdown("<h2>FTP Brute Force Attack</h2><ul><li> It's a way of cracking passwords by guessing. But these guesses, delivered one after another, are done very rapidly.</li></ul>",unsafe_allow_html=True)
    st.markdown("<h2>SSH Brute Force Attack</h2><ul><li>SSH brute force attacks are often achieved by an attacker trying a common username and password across thousands of servers until they find a match.</li></ul>",unsafe_allow_html=True)
    st.markdown("<h2>Slowloris</h2><ul><li>Slowloris is a type of denial of service attack tool which allows a single machine to take down another machine's web server with minimal bandwidth and side effects on unrelated services and ports.</li></ul>",unsafe_allow_html=True)
    st.markdown("<h2>High Orbit Ion Cannon</h2><ul><li>High Orbit Ion Cannon is an open-source network stress testing and denial-of-service attack application designed to attack as many as 256 URLs at the same time.</li></ul>",unsafe_allow_html=True)
    st.markdown("<h2>Infiltration</h2><ul><li>An insider threat is a malicious threat to an organization that comes from people within the organization, such as employees, former employees, contractors or business associates, who have inside information concerning the organization's security practices, data and computer systems.</li></ul>",unsafe_allow_html=True)
else:
    st.write("Upload the CSV file")
    uploadedfile=st.file_uploader("Upload")
    if uploadedfile is not None:
        df=pd.read_csv(uploadedfile)
        extra=df.iloc[:,0]
        data = df[lst[:-1]]
        
       
        inp = scaler.transform(data)
        
        pred = model.predict(inp)
        
        def highlight_intrusion(s):
                    return ['background-color: green']*len(s) if s['Predicted'] == "Benign" else ['background-color: red']*len(s)

        df['Predicted'] = encoder.inverse_transform(pred)
        df = df.drop(["Label"], axis=1)
        
        
        
        
        
        st.dataframe(df.style.apply(highlight_survived, axis=1))
        #st.dataframe(df.style.apply(highlight_intrusion, axis=1))

