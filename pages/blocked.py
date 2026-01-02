import streamlit as st

st.set_page_config(page_title="Access Denied", page_icon="⛔", layout="centered", initial_sidebar_state="collapsed")

st.markdown("""
<style>
    [data-testid="stAppViewContainer"] {
        background-color: #1E1E1E;
        color: white;
        text-align: center;
    }
</style>
""", unsafe_allow_html=True)

st.title("⛔ ACCESS BLOCKED")
st.error("Malicious Activity Detected by Killer Agent")

# Simulation of blocking action
col1, col2, col3 = st.columns([1, 2, 1])
with col2:
    st.image("https://media.giphy.com/media/v1.Y2lkPTc5MGI3NjExM3Z5Z3Z5Z3Z5Z3Z5Z3Z5Z3Z5Z3Z5Z3Z5Z3Z5Z3Z5/8L0PkyzC761YO/giphy.gif", caption="Killer Agent Active", use_container_width=True)

st.warning("Your IP address and activity have been logged for forensic analysis.")
