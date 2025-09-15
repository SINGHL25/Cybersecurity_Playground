import streamlit as st
import pandas as pd
from datetime import datetime

# Configure the Streamlit page
st.set_page_config(
    page_title="Cybersecurity Education Hub",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better styling
st.markdown("""
<style>
    .main-header {
        background: linear-gradient(90deg, #1e3a8a 0%, #3b82f6 100%);
        padding: 2rem;
        border-radius: 10px;
        color: white;
        text-align: center;
        margin-bottom: 2rem;
    }
    .feature-card {
        background: #f8fafc;
        border: 1px solid #e2e8f0;
        border-radius: 8px;
        padding: 1.5rem;
        margin: 1rem 0;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }
    .warning-box {
        background: #fef3c7;
        border-left: 4px solid #f59e0b;
        padding: 1rem;
        margin: 1rem 0;
        border-radius: 4px;
    }
    .success-box {
        background: #d1fae5;
        border-left: 4px solid #10b981;
        padding: 1rem;
        margin: 1rem 0;
        border-radius: 4px;
    }
</style>
""", unsafe_allow_html=True)

def main():
    # Main header
    st.markdown("""
    <div class="main-header">
        <h1>🛡️ Cybersecurity Education Hub</h1>
        <p>Learn cybersecurity through ethical, defensive practices and hands-on education</p>
    </div>
    """, unsafe_allow_html=True)

    # Sidebar navigation info
    st.sidebar.markdown("### 📚 Navigation")
    st.sidebar.markdown("Use the pages above to explore different cybersecurity topics:")
    st.sidebar.markdown("""
    - **Security Fundamentals**: Core concepts
    - **Threat Awareness**: Understanding attacks
    - **Defense Strategies**: Protection methods
    - **Risk Assessment**: Evaluation tools
    - **Password Checker**: Security analysis
    - **Network Security**: Configuration guides
    - **Security Audit**: Hardening checklists
    - **Incident Response**: Planning tools
    """)

    # Welcome section
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.markdown("""
        <div class="success-box">
            <h3>🎯 Welcome to Ethical Cybersecurity Learning!</h3>
            <p>This application focuses on <strong>defensive cybersecurity practices</strong> and educational content. 
            All tools and information are designed to help you understand how to <strong>protect</strong> systems and networks.</p>
        </div>
        """, unsafe_allow_html=True)

    with col2:
        st.markdown("""
        ### 📊 Learning Stats
        - **8** Educational modules
        - **Hands-on** defensive tools
        - **Interactive** learning experiences
        - **Career** guidance included
        """)

    # Key features
    st.markdown("## 🔧 Key Features")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.markdown("""
        <div class="feature-card">
            <h4>🎓 Educational Content</h4>
            <ul>
                <li>Security fundamentals</li>
                <li>Threat landscape overview</li>
                <li>Best practices guides</li>
                <li>Case study analysis</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        st.markdown("""
        <div class="feature-card">
            <h4>🛡️ Defensive Tools</h4>
            <ul>
                <li>Password strength analysis</li>
                <li>Security configuration guides</li>
                <li>Risk assessment tools</li>
                <li>Audit checklists</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        st.markdown("""
        <div class="feature-card">
            <h4>💼 Career Development</h4>
            <ul>
                <li>Certification guidance</li>
                <li>Skill development paths</li>
                <li>Industry insights</li>
                <li>Practice exercises</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)

    # Ethical guidelines
    st.markdown("## ⚖️ Ethical Guidelines")
    st.markdown("""
    <div class="warning-box">
        <h4>🚨 Important: Ethical Use Only</h4>
        <p>This application is designed for <strong>educational and defensive purposes only</strong>. All content focuses on:</p>
        <ul>
            <li>Understanding cybersecurity concepts theoretically</li>
            <li>Learning how to protect and defend systems</li>
            <li>Developing ethical cybersecurity skills</li>
            <li>Preparing for cybersecurity careers</li>
        </ul>
        <p><strong>Never use any knowledge gained here for malicious purposes or unauthorized access to systems.</strong></p>
    </div>
    """, unsafe_allow_html=True)

    # Learning path
    st.markdown("## 🗺️ Recommended Learning Path")
    
    learning_path = pd.DataFrame({
        "Step": [1, 2, 3, 4, 5, 6, 7, 8],
        "Module": [
            "Security Fundamentals",
            "Threat Awareness", 
            "Password Security",
            "Network Security",
            "Risk Assessment",
            "Security Auditing",
            "Defense Strategies",
            "Incident Response"
        ],
        "Description": [
            "Learn core cybersecurity concepts and terminology",
            "Understand common threats and attack vectors",
            "Analyze and improve password security practices",
            "Configure secure network settings and protocols",
            "Assess and manage cybersecurity risks",
            "Perform security audits and hardening",
            "Implement comprehensive defense strategies",
            "Plan and execute incident response procedures"
        ],
        "Difficulty": [
            "Beginner", "Beginner", "Beginner", "Intermediate",
            "Intermediate", "Intermediate", "Advanced", "Advanced"
        ]
    })
    
    st.dataframe(learning_path, use_container_width=True)

    # Quick stats
    st.markdown("## 📈 Cybersecurity Facts")
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Cyber Attacks Daily", "4,000+", help="Average number of cyber attacks per day globally")
    
    with col2:
        st.metric("Data Breach Cost", "$4.45M", help="Average cost of a data breach in 2023")
    
    with col3:
        st.metric("Cybersecurity Jobs", "3.5M", help="Estimated cybersecurity job shortage globally")
    
    with col4:
        st.metric("Security Spending", "$188B", help="Global cybersecurity spending in 2023")

    # Getting started
    st.markdown("## 🚀 Getting Started")
    st.markdown("""
    1. **Start with Security Fundamentals** - Build your foundation knowledge
    2. **Explore Threat Awareness** - Understand what you're defending against
    3. **Use the Password Checker** - Practice with hands-on tools
    4. **Review Defense Strategies** - Learn protection methods
    5. **Try Risk Assessment** - Evaluate security postures
    6. **Practice with Auditing Tools** - Hands-on security checking
    7. **Plan Incident Response** - Prepare for security events
    
    💡 **Tip**: Work through the modules in order for the best learning experience!
    """)

    # Footer
    st.markdown("---")
    st.markdown("""
    <div style="text-align: center; color: #64748b; padding: 1rem;">
        <p>🛡️ Cybersecurity Education Hub - Focused on Ethical Learning and Defense</p>
        <p>Remember: Use your cybersecurity knowledge to protect and defend, never to attack or harm.</p>
    </div>
    """, unsafe_allow_html=True)

if __name__ == "__main__":
    main()
