# pages/1_Security_Fundamentals.py

import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd

st.set_page_config(
    page_title="Security Fundamentals",
    page_icon="🔐",
    layout="wide"
)

st.markdown("""
<style>
    .concept-card {
        background: #f8fafc;
        border: 1px solid #e2e8f0;
        border-radius: 8px;
        padding: 1.5rem;
        margin: 1rem 0;
    }
    .definition-box {
        background: #eff6ff;
        border-left: 4px solid #3b82f6;
        padding: 1rem;
        margin: 1rem 0;
        border-radius: 4px;
    }
    .quiz-section {
        background: #f0fdf4;
        border: 1px solid #bbf7d0;
        border-radius: 8px;
        padding: 1.5rem;
        margin: 2rem 0;
    }
</style>
""", unsafe_allow_html=True)

def main():
    st.title("🔐 Security Fundamentals")
    st.markdown("**Learn the core concepts that form the foundation of cybersecurity**")
    
    # Navigation tabs
    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "CIA Triad", "Authentication", "Risk Management", "Security Controls", "Knowledge Quiz"
    ])
    
    with tab1:
        cia_triad_section()
    
    with tab2:
        authentication_section()
    
    with tab3:
        risk_management_section()
    
    with tab4:
        security_controls_section()
    
    with tab5:
        knowledge_quiz()

def cia_triad_section():
    st.header("🔺 The CIA Triad")
    st.markdown("The CIA Triad is the foundational model for cybersecurity, consisting of three key principles:")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.markdown("""
        <div class="concept-card">
            <h4>🔒 Confidentiality</h4>
            <p><strong>Definition:</strong> Ensuring information is accessible only to authorized individuals.</p>
            <p><strong>Examples:</strong></p>
            <ul>
                <li>Encryption of sensitive data</li>
                <li>Access controls and permissions</li>
                <li>Need-to-know basis policies</li>
                <li>Data classification systems</li>
            </ul>
            <p><strong>Threats:</strong> Data breaches, unauthorized access, eavesdropping</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        st.markdown("""
        <div class="concept-card">
            <h4>✅ Integrity</h4>
            <p><strong>Definition:</strong> Maintaining accuracy and completeness of data and systems.</p>
            <p><strong>Examples:</strong></p>
            <ul>
                <li>Checksums and hash functions</li>
                <li>Digital signatures</li>
                <li>Version control systems</li>
                <li>Backup and recovery procedures</li>
            </ul>
            <p><strong>Threats:</strong> Data tampering, malware, unauthorized modifications</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        st.markdown("""
        <div class="concept-card">
            <h4>🟢 Availability</h4>
            <p><strong>Definition:</strong> Ensuring systems and data are accessible when needed.</p>
            <p><strong>Examples:</strong></p>
            <ul>
                <li>Redundant systems and backups</li>
                <li>Load balancing</li>
                <li>Disaster recovery plans</li>
                <li>System maintenance schedules</li>
            </ul>
            <p><strong>Threats:</strong> DDoS attacks, hardware failures, natural disasters</p>
        </div>
        """, unsafe_allow_html=True)
    
    # CIA Triad visualization
    st.subheader("🎯 CIA Triad Balance")
    
    fig = go.Figure()
    fig.add_trace(go.Scatterpolar(
        r=[9, 8, 7, 9],
        theta=['Confidentiality', 'Integrity', 'Availability', 'Confidentiality'],
        fill='toself',
        name='Ideal Security Posture',
        line_color='blue'
    ))
    
    fig.update_layout(
        polar=dict(
            radialaxis=dict(
                visible=True,
                range=[0, 10]
            )
        ),
        showlegend=True,
        title="Security Posture Assessment"
    )
    
    st.plotly_chart(fig, use_container_width=True)

def authentication_section():
    st.header("🔑 Authentication & Access Control")
    
    st.markdown("""
    <div class="definition-box">
        <h4>Authentication vs Authorization</h4>
        <p><strong>Authentication:</strong> "Who are you?" - Verifying identity</p>
        <p><strong>Authorization:</strong> "What can you do?" - Granting permissions</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Authentication factors
    st.subheader("🎯 Authentication Factors")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        ### The Three Factors:
        
        **🧠 Something you know (Knowledge)**
        - Passwords
        - PINs
        - Security questions
        - Passphrases
        
        **📱 Something you have (Possession)**
        - Smart cards
        - Tokens
        - Mobile devices
        - Hardware keys
        
        **👤 Something you are (Inherence)**
        - Fingerprints
        - Retinal scans
        - Voice recognition
        - Facial recognition
        """)
    
    with col2:
        # Multi-factor authentication strength chart
        mfa_data = pd.DataFrame({
            'Method': ['Single Factor', '2FA (Knowledge + Possession)', '2FA (Knowledge + Biometric)', '3FA (All Factors)'],
            'Security Level': [3, 7, 8, 10],
            'User Convenience': [10, 6, 7, 4]
        })
        
        fig = px.scatter(mfa_data, x='User Convenience', y='Security Level', 
                        size=[20, 40, 45, 50], color='Method',
                        title="Security vs Convenience Trade-off")
        fig.update_layout(
            xaxis_title="User Convenience (Higher = More Convenient)",
            yaxis_title="Security Level (Higher = More Secure)"
        )
        st.plotly_chart(fig, use_container_width=True)

def risk_management_section():
    st.header("⚖️ Risk Management")
    
    st.markdown("""
    <div class="definition-box">
        <h4>Risk Formula</h4>
        <p><strong>Risk = Threat × Vulnerability × Impact</strong></p>
        <p>Understanding and managing risk is essential for effective cybersecurity.</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Risk assessment matrix
    st.subheader("📊 Risk Assessment Matrix")
    
    # Interactive risk calculator
    col1, col2 = st.columns([1, 2])
    
    with col1:
        st.markdown("### Risk Calculator")
        threat_level = st.slider("Threat Level", 1, 5, 3, help="How likely is the threat?")
        vulnerability_level = st.slider("Vulnerability Level", 1, 5, 3, help="How exploitable is the weakness?")
        impact_level = st.slider("Impact Level", 1, 5, 3, help="How severe would the consequences be?")
        
        risk_score = threat_level * vulnerability_level * impact_level
        
        if risk_score <= 25:
            risk_category = "Low"
            risk_color = "green"
        elif risk_score <= 75:
            risk_category = "Medium"
            risk_color = "orange"
        else:
            risk_category = "High"
            risk_color = "red"
        
        st.markdown(f"""
        ### Risk Assessment Result:
        **Score:** {risk_score}/125  
        **Category:** <span style="color: {risk_color}; font-weight: bold;">{risk_category} Risk</span>
        """, unsafe_allow_html=True)
    
    with col2:
        # Risk matrix visualization
        risk_matrix = [[1, 2, 3, 4, 5],
                      [2, 4, 6, 8, 10],
                      [3, 6, 9, 12, 15],
                      [4, 8, 12, 16, 20],
                      [5, 10, 15, 20, 25]]
        
        fig = px.imshow(risk_matrix,
                       labels=dict(x="Impact", y="Likelihood", color="Risk Score"),
                       x=['Very Low', 'Low', 'Medium', 'High', 'Very High'],
                       y=['Very High', 'High', 'Medium', 'Low', 'Very Low'],
                       color_continuous_scale='RdYlGn_r',
                       title="Risk Assessment Matrix")
        
        st.plotly_chart(fig, use_container_width=True)

def security_controls_section():
    st.header("🛡️ Security Controls")
    
    st.markdown("Security controls are measures implemented to reduce risk and protect assets.")
    
    # Types of controls
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.markdown("""
        <div class="concept-card">
            <h4>🚧 Preventive Controls</h4>
            <p><strong>Purpose:</strong> Stop incidents before they occur</p>
            <p><strong>Examples:</strong></p>
            <ul>
                <li>Firewalls</li>
                <li>Access controls</li>
                <li>Encryption</li>
                <li>Security training</li>
                <li>Antivirus software</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        st.markdown("""
        <div class="concept-card">
            <h4>🔍 Detective Controls</h4>
            <p><strong>Purpose:</strong> Identify incidents as they occur</p>
            <p><strong>Examples:</strong></p>
            <ul>
                <li>Intrusion detection systems</li>
                <li>Security monitoring</li>
                <li>Audit logs</li>
                <li>Security cameras</li>
                <li>Vulnerability scans</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        st.markdown("""
        <div class="concept-card">
            <h4>🔧 Corrective Controls</h4>
            <p><strong>Purpose:</strong> Respond to and recover from incidents</p>
            <p><strong>Examples:</strong></p>
            <ul>
                <li>Incident response plans</li>
                <li>Backup systems</li>
                <li>Patch management</li>
                <li>Disaster recovery</li>
                <li>Security updates</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)
    
    # Defense in depth
    st.subheader("🏰 Defense in Depth")
    st.markdown("""
    Defense in depth is a layered security approach that uses multiple security controls 
    to protect assets. If one layer fails, others continue to provide protection.
    """)
    
    # Layered defense visualization
    layers = ['Physical Security', 'Network Security', 'Host Security', 'Application Security', 'Data Security']
    layer_strength = [85, 78, 82, 75, 90]
    
    fig = px.bar(x=layers, y=layer_strength, title="Defense Layer Effectiveness",
                labels={'x': 'Security Layer', 'y': 'Effectiveness (%)'})
    fig.update_traces(marker_color=['#ff6b6b', '#4ecdc4', '#45b7d1', '#96ceb4', '#feca57'])
    st.plotly_chart(fig, use_container_width=True)

def knowledge_quiz():
    st.header("🧠 Knowledge Quiz")
    st.markdown("Test your understanding of security fundamentals!")
    
    st.markdown("""
    <div class="quiz-section">
        <h4>Interactive Learning Quiz</h4>
        <p>Answer these questions to reinforce your learning:</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Quiz questions
    questions = [
        {
            "question": "Which component of the CIA Triad focuses on ensuring data hasn't been tampered with?",
            "options": ["Confidentiality", "Integrity", "Availability", "Authentication"],
            "correct": 1,
            "explanation": "Integrity ensures data accuracy and prevents unauthorized modifications."
        },
        {
            "question": "What authentication factor is a password?",
            "options": ["Something you are", "Something you have", "Something you know", "Something you do"],
            "correct": 2,
            "explanation": "A password is 'something you know' - knowledge-based authentication."
        },
        {
            "question": "Which type of control is designed to prevent incidents before they occur?",
            "options": ["Detective", "Corrective", "Preventive", "Reactive"],
            "correct": 2,
            "explanation": "Preventive controls stop incidents before they happen, like firewalls and access controls."
        }
    ]
    
    score = 0
    total_questions = len(questions)
    
    for i, q in enumerate(questions):
        st.subheader(f"Question {i+1}")
        st.write(q["question"])
        
        user_answer = st.radio(f"Select your answer for question {i+1}:", 
                             q["options"], key=f"q{i}")
        
        if st.button(f"Check Answer {i+1}", key=f"check{i}"):
            if q["options"].index(user_answer) == q["correct"]:
                st.success("✅ Correct!")
                score += 1
            else:
                st.error(f"❌ Incorrect. The correct answer is: {q['options'][q['correct']]}")
            st.info(f"💡 Explanation: {q['explanation']}")
        
        st.markdown("---")
    
    # Final score
    if st.button("Calculate Final Score"):
        percentage = (score / total_questions) * 100
        st.markdown(f"### 🎯 Your Score: {score}/{total_questions} ({percentage:.1f}%)")
        
        if percentage >= 80:
            st.success("🏆 Excellent! You have a strong understanding of security fundamentals.")
        elif percentage >= 60:
            st.warning("👍 Good job! Review the areas where you missed questions.")
        else:
            st.error("📚 Keep studying! Review the material and try again.")

    # Additional resources
    st.markdown("## 📚 Additional Resources")
    st.markdown("""
    **Recommended Reading:**
    - NIST Cybersecurity Framework
    - ISO 27001 Security Standards
    - OWASP Security Guidelines
    
    **Practice Opportunities:**
    - Security+ Certification Study Materials
    - Cybersecurity Awareness Training
    - Hands-on Lab Exercises
    
    **Stay Updated:**
    - Follow cybersecurity news and blogs
    - Join professional organizations
    - Attend security conferences and webinars
    """)

if __name__ == "__main__":
    main()
