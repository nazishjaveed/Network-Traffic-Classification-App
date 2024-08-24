import streamlit as st
import pandas as pd
import joblib

# Load the model and scaler
model = joblib.load('model.pkl')
scaler = joblib.load('scaler.pkl')

# Define the Streamlit app
st.title("Network Traffic Classification App")

# Sidebar for user input
st.sidebar.header("User Input Parameters")

def user_input_features():
    dur = st.sidebar.number_input('Duration', min_value=0.0, max_value=1000.0, value=0.0)
    proto = st.sidebar.selectbox('Protocol', [0, 1, 2])  # Adjust according to your encoding
    service = st.sidebar.selectbox('Service', [0, 1, 2])  # Adjust according to your encoding
    state = st.sidebar.selectbox('State', [0, 1, 2])  # Adjust according to your encoding
    spkts = st.sidebar.number_input('Source Packets', min_value=0, max_value=10000, value=0)
    dpkts = st.sidebar.number_input('Destination Packets', min_value=0, max_value=10000, value=0)
    sbytes = st.sidebar.number_input('Source Bytes', min_value=0, max_value=1000000, value=0)
    dbytes = st.sidebar.number_input('Destination Bytes', min_value=0, max_value=1000000, value=0)
    rate = st.sidebar.number_input('Rate', min_value=0.0, max_value=10000.0, value=0.0)
    sttl = st.sidebar.number_input('Source TTL', min_value=0, max_value=255, value=0)
    dttl = st.sidebar.number_input('Destination TTL', min_value=0, max_value=255, value=0)
    sload = st.sidebar.number_input('Source Load', min_value=0.0, max_value=1000000.0, value=0.0)
    dload = st.sidebar.number_input('Destination Load', min_value=0.0, max_value=1000000.0, value=0.0)
    sloss = st.sidebar.number_input('Source Loss', min_value=0, max_value=1000, value=0)
    dloss = st.sidebar.number_input('Destination Loss', min_value=0, max_value=1000, value=0)
    sinpkt = st.sidebar.number_input('Source Inter-packet Time', min_value=0.0, max_value=1000.0, value=0.0)
    dinpkt = st.sidebar.number_input('Destination Inter-packet Time', min_value=0.0, max_value=1000.0, value=0.0)
    sjit = st.sidebar.number_input('Source Jitter', min_value=0.0, max_value=1000.0, value=0.0)
    djit = st.sidebar.number_input('Destination Jitter', min_value=0.0, max_value=1000.0, value=0.0)
    swin = st.sidebar.number_input('Source Window Size', min_value=0, max_value=100000, value=0)
    stcpb = st.sidebar.number_input('Source TCP Base', min_value=0, max_value=1000000000, value=0)
    dtcpb = st.sidebar.number_input('Destination TCP Base', min_value=0, max_value=1000000000, value=0)
    dwin = st.sidebar.number_input('Destination Window Size', min_value=0, max_value=100000, value=0)
    tcprtt = st.sidebar.number_input('TCP RTT', min_value=0.0, max_value=1000.0, value=0.0)
    synack = st.sidebar.number_input('SYN ACK', min_value=0.0, max_value=1000.0, value=0.0)
    ackdat = st.sidebar.number_input('ACK Data', min_value=0.0, max_value=1000.0, value=0.0)
    smean = st.sidebar.number_input('Source Mean', min_value=0.0, max_value=10000.0, value=0.0)
    dmean = st.sidebar.number_input('Destination Mean', min_value=0.0, max_value=10000.0, value=0.0)
    trans_depth = st.sidebar.number_input('Transaction Depth', min_value=0, max_value=1000, value=0)
    response_body_len = st.sidebar.number_input('Response Body Length', min_value=0, max_value=100000, value=0)
    ct_srv_src = st.sidebar.number_input('ct_srv_src', min_value=0, max_value=1000, value=0)
    ct_state_ttl = st.sidebar.number_input('ct_state_ttl', min_value=0, max_value=1000, value=0)
    ct_dst_ltm = st.sidebar.number_input('ct_dst_ltm', min_value=0, max_value=1000, value=0)
    ct_src_dport_ltm = st.sidebar.number_input('ct_src_dport_ltm', min_value=0, max_value=1000, value=0)
    ct_dst_sport_ltm = st.sidebar.number_input('ct_dst_sport_ltm', min_value=0, max_value=1000, value=0)
    ct_dst_src_ltm = st.sidebar.number_input('ct_dst_src_ltm', min_value=0, max_value=1000, value=0)
    is_ftp_login = st.sidebar.selectbox('is_ftp_login', [0, 1])
    ct_ftp_cmd = st.sidebar.number_input('ct_ftp_cmd', min_value=0, max_value=1000, value=0)
    ct_flw_http_mthd = st.sidebar.number_input('ct_flw_http_mthd', min_value=0, max_value=1000, value=0)
    ct_src_ltm = st.sidebar.number_input('ct_src_ltm', min_value=0, max_value=1000, value=0)
    ct_srv_dst = st.sidebar.number_input('ct_srv_dst', min_value=0, max_value=1000, value=0)
    is_sm_ips_ports = st.sidebar.selectbox('is_sm_ips_ports', [0, 1])
    attack_cat = st.sidebar.selectbox('attack_cat', [0, 1, 2, 3, 4, 5, 6, 7])  # Adjust according to your encoding

    data = {
        'dur': dur,
        'proto': proto,
        'service': service,
        'state': state,
        'spkts': spkts,
        'dpkts': dpkts,
        'sbytes': sbytes,
        'dbytes': dbytes,
        'rate': rate,
        'sttl': sttl,
        'dttl': dttl,
        'sload': sload,
        'dload': dload,
        'sloss': sloss,
        'dloss': dloss,
        'sinpkt': sinpkt,
        'dinpkt': dinpkt,
        'sjit': sjit,
        'djit': djit,
        'swin': swin,
        'stcpb': stcpb,
        'dtcpb': dtcpb,
        'dwin': dwin,
        'tcprtt': tcprtt,
        'synack': synack,
        'ackdat': ackdat,
        'smean': smean,
        'dmean': dmean,
        'trans_depth': trans_depth,
        'response_body_len': response_body_len,
        'ct_srv_src': ct_srv_src,
        'ct_state_ttl': ct_state_ttl,
        'ct_dst_ltm': ct_dst_ltm,
        'ct_src_dport_ltm': ct_src_dport_ltm,
        'ct_dst_sport_ltm': ct_dst_sport_ltm,
        'ct_dst_src_ltm': ct_dst_src_ltm,
        'is_ftp_login': is_ftp_login,
        'ct_ftp_cmd': ct_ftp_cmd,
        'ct_flw_http_mthd': ct_flw_http_mthd,
        'ct_src_ltm': ct_src_ltm,
        'ct_srv_dst': ct_srv_dst,
        'is_sm_ips_ports': is_sm_ips_ports,
        'attack_cat': attack_cat,
    }
    features = pd.DataFrame(data, index=[0])
    return features

# Main panel for displaying results
df = user_input_features()

st.subheader('User Input Parameters')
st.write(df)

# Scale the input data
scaled_df = scaler.transform(df)

# Predict the class
prediction = model.predict(scaled_df)

st.subheader('Prediction')
st.write(prediction)

# Optionally, display prediction probability
prediction_proba = model.predict_proba(scaled_df)
st.subheader('Prediction Probability')
st.write(prediction_proba)