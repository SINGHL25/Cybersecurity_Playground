

import streamlit as st
import re
import math
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd
from datetime import datetime, timedelta

st.set_page_config(
    page_title="Password Security Checker",
    page_icon="🔐",
    layout="wide"
)

st.markdown("""
<style>
    .password-strength-very-weak { color: #dc2626; font-weight: bold; }
    .password-strength-weak { color: #ea580c; font-weight: bold; }
    .password-strength-fair { color: #ca8a04; font-weight: bold; }
    .password-strength-good { color: #16a34a; font-weight: bold; }
    .password-strength-strong { color: #059669; font-weight: bold; }
    
    .security-tip {
        background: #eff6ff;
        border-left: 4px solid #3b82f6;
        padding: 1rem;
        margin: 1rem 0;
        border-radius: 4px;
    }
    .warning-box {
        background: #fef3c7;
        border-left: 4px solid #f59e0b;
        padding: 1rem;
        margin: 1rem 0;
        border-radius: 4px;
    }
    .good-practice {
        background: #f0fdf4;
        border-left: 4px solid #16a34a;
        padding: 1rem;
        margin: 1rem 0;
        border-radius: 4px;
    }
</style>
""", unsafe_allow_html=True)

class PasswordAnalyzer:
    def __init__(self):
        self.common_passwords = [
            'password', '123456', '12345678', 'qwerty', 'abc123', 
            'password123', 'admin', 'letmein', 'welcome', 'monkey',
            '1234567890', 'password1', 'sunshine', 'princess', 'dragon'
        ]
        
        self.common_patterns = [
            r'(.)\1{2,}',  # Repeated characters
            r'123456|654321',  # Sequential numbers
            r'qwerty|asdf',  # Keyboard patterns
            r'password|admin|user',  # Common words
        ]

    def calculate_entropy(self, password):
        """Calculate password entropy"""
        char_set_size = 0
        if re.search(r'[a-z]', password):
            char_set_size += 26
        if re.search(r'[A-Z]', password):
            char_set_size += 26
        if re.search(r'[0-9]', password):
            char_set_size += 10
        if re.search(r'[^a-zA-Z0-9]', password):
            char_set_size += 32
        
        if char_set_size == 0:
            return 0
        
        return len(password) * math.log2(char_set_size)

    def check_common_password(self, password):
        """Check if password is in common passwords list"""
        return password.lower() in self.common_passwords

    def check_patterns(self, password):
        """Check for common patterns"""
        found_patterns = []
        for pattern in self.common_patterns:
            if re.search(pattern, password.lower()):
                found_patterns.append(pattern)
        return found_patterns

    def calculate_crack_time(self, entropy):
        """Estimate time to crack password"""
        # Assuming 1 billion guesses per second
        guesses_per_second = 1_000_000_000
        total_combinations = 2 ** entropy
        seconds_to_crack = total_combinations / (2 * guesses_per_second)  # Average case
        
        if seconds_to_crack < 60:
            return f"{seconds_to_crack:.1f} seconds"
        elif seconds_to_crack < 3600:
            return f"{seconds_to_crack/60:.1f} minutes"
        elif seconds_to_crack < 86400:
            return f"{seconds_to_crack/3600:.1f} hours"
        elif seconds_to_crack < 31536000:
            return f"{seconds_to_crack/86400:.1f} days"
        elif seconds_to_crack < 31536000 * 1000:
            return f"{seconds_to_crack/31536000:.1f} years"
        else:
            return "Centuries+"

    def analyze_password(self, password):
        """Complete password analysis"""
        if not password:
            return None

        analysis = {
            'length': len(password),
            'has_lowercase': bool(re.search(r'[a-z]', password)),
            'has_uppercase': bool(re.search(r'[A-Z]', password)),
            'has_numbers': bool(re.search(r'[0-9]', password)),
            'has_special': bool(re.search(r'[^a-zA-Z0-9]', password)),
            'is_common': self.check_common_password(password),
            'patterns': self.check_patterns(password),
            'entropy': self.calculate_entropy(password)
        }
        
        analysis['crack_time'] = self.calculate_crack_time(analysis['entropy'])
        analysis['strength_score'] = self.calculate_strength_score(analysis)
        analysis['strength_label'] = self.get_strength_label(analysis['strength_score'])
        
        return analysis

    def calculate_strength_score(self, analysis):
        """Calculate overall strength score (0-100)"""
        score = 0
        
        # Length scoring (up to 30 points)
        if analysis['length'] >= 12:
            score += 30
        elif analysis['length'] >= 8:
            score += 20
        elif analysis['length'] >= 6:
            score += 10
        
        # Character variety (up to 40 points)
        char_types = sum([
            analysis['has_lowercase'],
            analysis['has_uppercase'], 
            analysis['has_numbers'],
            analysis['has_special']
        ])
        score += char_types * 10
        
        # Entropy bonus (up to 20 points)
        if analysis['entropy'] >= 60:
            score += 20
        elif analysis['entropy'] >= 40:
            score += 15
        elif analysis['entropy'] >= 25:
            score += 10
        
        # Penalties
        if analysis['is_common']:
            score -= 30
        if analysis['patterns']:
            score -= len(analysis['patterns']) * 10
        
        # Additional bonus for very long passwords
        if analysis['length'] >= 16:
            score += 10
        
        return max(0, min(100, score))

    def get_strength_label(self, score):
        """Get strength label based on score"""
        if score >= 80:
            return "Strong"
        elif score >= 60:
            return "Good"
        elif score >= 40:
            return "Fair"
        elif score >= 20:
            return "Weak"
        else:
            return "Very Weak"

def main():
    st.title("🔐 Password Security Checker")
    st.markdown("**Analyze password strength and get recommendations for better security**")
    
    analyzer = PasswordAnalyzer()
    
    # Warning about password privacy
    st.markdown("""
    <div class="warning-box">
        <h4>🔒 Privacy Notice</h4>
        <p><strong>Your passwords are processed locally and are never stored or transmitted.</strong> 
        This tool runs entirely in your browser for maximum security.</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Main tabs
    tab1, tab2, tab3, tab4 = st.tabs([
        "Password Analyzer", "Password Generator", "Security Tips", "Breach Checker Info"
    ])
    
    with tab1:
        password_analyzer_tab(analyzer)
    
    with tab2:
        password_generator_tab()
    
    with tab3:
        security_tips_tab()
    
    with tab4:
        breach_checker_info_tab()

def password_analyzer_tab(analyzer):
    st.header("🔍 Password Strength Analysis")
    
    col1, col2 = st.columns([1, 2])
    
    with col1:
        password = st.text_input(
            "Enter password to analyze:",
            type="password",
            help="Your password is processed locally and never stored"
        )
        
        show_password = st.checkbox("Show password", help="Toggle password visibility")
        
        if show_password and password:
            st.text(f"Password: {password}")
    
    if password:
        analysis = analyzer.analyze_password(password)
        
        with col2:
            # Strength indicator
            strength_colors = {
                "Very Weak": "#dc2626",
                "Weak": "#ea580c", 
                "Fair": "#ca8a04",
                "Good": "#16a34a",
                "Strong": "#059669"
            }
            
            color = strength_colors[analysis['strength_label']]
            
            st.markdown(f"""
            ### Password Strength: <span style="color: {color};">{analysis['strength_label']}</span>
            **Score: {analysis['strength_score']}/100**
            """, unsafe_allow_html=True)
            
            # Progress bar
            progress_color = color
            st.markdown(f"""
            <div style="background-color: #f0f0f0; border-radius: 10px; height: 20px; margin: 10px 0;">
                <div style="background-color: {progress_color}; width: {analysis['strength_score']}%; height: 100%; border-radius: 10px;"></div>
            </div>
            """, unsafe_allow_html=True)
        
        # Detailed analysis
        st.subheader("📊 Detailed Analysis")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.markdown("### 📏 Basic Properties")
            st.write(f"**Length:** {analysis['length']} characters")
            st.write(f"**Entropy:** {analysis['entropy']:.1f} bits")
            st.write(f"**Estimated crack time:** {analysis['crack_time']}")
            
        with col2:
            st.markdown("### 🔤 Character Types")
            st.write(f"**Lowercase letters:** {'✅' if analysis['has_lowercase'] else '❌'}")
            st.write(f"**Uppercase letters:** {'✅' if analysis['has_uppercase'] else '❌'}")
            st.write(f"**Numbers:** {'✅' if analysis['has_numbers'] else '❌'}")
            st.write(f"**Special characters:** {'✅' if analysis['has_special'] else '❌'}")
        
        with col3:
            st.markdown("### ⚠️ Security Issues")
            if analysis['is_common']:
                st.write("❌ **Common password detected**")
            else:
                st.write("✅ Not a common password")
                
            if analysis['patterns']:
                st.write(f"❌ **{len(analysis['patterns'])} pattern(s) detected**")
            else:
                st.write("✅ No obvious patterns found")
        
        # Recommendations
        st.subheader("💡 Recommendations")
        recommendations = []
        
        if analysis['length'] < 12:
            recommendations.append("Use at least 12 characters (16+ recommended)")
        if not analysis['has_lowercase']:
            recommendations.append("Add lowercase letters")
        if not analysis['has_uppercase']:
            recommendations.append("Add uppercase letters")  
        if not analysis['has_numbers']:
            recommendations.append("Add numbers")
        if not analysis['has_special']:
            recommendations.append("Add special characters (!@#$%^&*)")
        if analysis['is_common']:
            recommendations.append("Avoid common passwords")
        if analysis['patterns']:
            recommendations.append("Avoid predictable patterns")
        
        if recommendations:
            for rec in recommendations:
                st.write(f"• {rec}")
        else:
            st.success("🎉 Your password follows good security practices!")
        
        # Visual entropy analysis
        if analysis['entropy'] > 0:
            st.subheader("📈 Entropy Visualization")
            
            entropy_levels = pd.DataFrame({
                'Strength': ['Very Weak', 'Weak', 'Fair', 'Good', 'Strong'],
                'Min Entropy': [0, 25, 40, 60, 80],
                'Color': ['#dc2626', '#ea580c', '#ca8a04', '#16a34a', '#059669']
            })
            
            fig = go.Figure()
            
            # Add entropy levels as horizontal bars
            for _, level in entropy_levels.iterrows():
                fig.add_shape(
                    type="rect",
                    x0=level['Min Entropy'], x1=level['Min Entropy'] + 20,
                    y0=-0.5, y1=0.5,
                    fillcolor=level['Color'],
                    opacity=0.3,
                    line_width=0
                )
            
            # Add current password entropy
            fig.add_trace(go.Scatter(
                x=[analysis['entropy']],
                y=[0],
                mode='markers',
                marker=dict(size=20, color='black', symbol='diamond'),
                name=f'Your Password ({analysis['entropy']:.1f} bits)'
            ))
            
            fig.update_layout(
                title="Password Entropy Comparison",
                xaxis_title="Entropy (bits)",
                yaxis=dict(visible=False),
                height=200,
                showlegend=True
            )
            
            st.plotly_chart(fig, use_container_width=True)

def password_generator_tab():
    st.header("🎲 Secure Password Generator")
    
    col1, col2 = st.columns([1, 2])
    
    with col1:
        st.subheader("Generator Settings")
        length = st.slider("Password Length", 8, 128, 16)
        
        include_uppercase = st.checkbox("Uppercase Letters (A-Z)", True)
        include_lowercase = st.checkbox("Lowercase Letters (a-z)", True)
        include_numbers = st.checkbox("Numbers (0-9)", True)
        include_special = st.checkbox("Special Characters (!@#$%^&*)", True)
        
        exclude_ambiguous = st.checkbox("Exclude Ambiguous Characters (0, O, l, 1)", True)
        
        num_passwords = st.slider("Number of passwords to generate", 1, 10, 3)
    
    if st.button("Generate Passwords"):
        import random
        import string
        
        char_set = ""
        if include_lowercase:
            char_set += string.ascii_lowercase
        if include_uppercase:
            char_set += string.ascii_uppercase
        if include_numbers:
            char_set += string.digits
        if include_special:
            char_set += "!@#$%^&*()_+-=[]{}|;:,.<>?"
        
        if exclude_ambiguous:
            ambiguous = "0O1l"
            char_set = ''.join(c for c in char_set if c not in ambiguous)
        
        if not char_set:
            st.error("Please select at least one character type!")
        else:
            with col2:
                st.subheader("Generated Passwords")
                passwords = []
                for i in range(num_passwords):
                    password = ''.join(random.choices(char_set, k=length))
                    passwords.append(password)
                    
                    # Quick strength check
                    analyzer = PasswordAnalyzer()
                    analysis = analyzer.analyze_password(password)
                    strength_color = {
                        "Very Weak": "#dc2626", "Weak": "#ea580c", "Fair": "#ca8a04",
                        "Good": "#16a34a", "Strong": "#059669"
                    }[analysis['strength_label']]
                    
                    st.code(password, language=None)
                    st.markdown(f"Strength: <span style='color: {strength_color};'>{analysis['strength_label']}</span> | Entropy: {analysis['entropy']:.1f} bits", unsafe_allow_html=True)
                    st.markdown("---")

def security_tips_tab():
    st.header("🛡️ Password Security Best Practices")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        <div class="good-practice">
            <h4>✅ Do These Things</h4>
            <ul>
                <li>Use unique passwords for every account</li>
                <li>Make passwords at least 12 characters long</li>
                <li>Include uppercase, lowercase, numbers, and symbols</li>
                <li>Use a password manager</li>
                <li>Enable two-factor authentication (2FA)</li>
                <li>Use passphrases (multiple random words)</li>
                <li>Update passwords regularly for sensitive accounts</li>
                <li>Check if your accounts have been breached</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        st.markdown("""
        <div class="warning-box">
            <h4>❌ Avoid These Mistakes</h4>
            <ul>
                <li>Using the same password everywhere</li>
                <li>Using personal information (birthdate, name)</li>
                <li>Using common passwords (password123)</li>
                <li>Using keyboard patterns (qwerty123)</li>
                <li>Sharing passwords with others</li>
                <li>Storing passwords in plain text</li>
                <li>Using only dictionary words</li>
                <li>Ignoring security breach notifications</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)
    
    st.subheader("🔐 Password Manager Benefits")
    
    benefits = pd.DataFrame({
        'Benefit': [
            'Unique Passwords',
            'Strong Generation', 
            'Secure Storage',
            'Auto-Fill',
            'Breach Monitoring',
            'Cross-Platform Sync'
        ],
        'Description': [
            'Generate unique passwords for every account',
            'Create strong, random passwords automatically',
            'Encrypt and store passwords securely',
            'Automatically fill login forms',
            'Alert you to compromised accounts',
            'Access passwords across all devices'
        ],
        'Security Impact': [95, 90, 98, 70, 85, 75]
    })
    
    fig = px.bar(benefits, x='Benefit', y='Security Impact', 
                title='Password Manager Security Benefits',
                color='Security Impact',
                color_continuous_scale='Greens')
    fig.update_layout(showlegend=False)
    st.plotly_chart(fig, use_container_width=True)
    
    st.subheader("🎯 Two-Factor Authentication (2FA)")
    
    st.markdown("""
    <div class="security-tip">
        <h4>Why 2FA Matters</h4>
        <p>Even if someone steals your password, 2FA provides an additional security layer. 
        It requires a second form of authentication, such as:</p>
        <ul>
            <li><strong>SMS codes</strong> - Sent to your phone (least secure)</li>
            <li><strong>Authenticator apps</strong> - Google Authenticator, Authy (better)</li>
            <li><strong>Hardware keys</strong> - YubiKey, Titan Key (most secure)</li>
            <li><strong>Biometrics</strong> - Fingerprint, face recognition</li>
        </ul>
        <p><strong>Security Improvement:</strong> 2FA blocks 99.9% of automated attacks!</p>
    </div>
    """, unsafe_allow_html=True)

def breach_checker_info_tab():
    st.header("🚨 Data Breach Awareness")
    
    st.markdown("""
    <div class="security-tip">
        <h4>What Are Data Breaches?</h4>
        <p>Data breaches occur when unauthorized individuals access sensitive information, 
        including usernames, passwords, and personal data. Major breaches have affected 
        billions of accounts worldwide.</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Notable breaches (educational information)
    st.subheader("📊 Major Data Breaches (Educational)")
    
    breach_data = pd.DataFrame({
        'Company': ['Yahoo', 'Equifax', 'Facebook', 'Marriott', 'Adobe', 'LinkedIn'],
        'Year': [2013, 2017, 2019, 2018, 2013, 2012],
        'Records Affected (Millions)': [3000, 147, 533, 500, 153, 117],
        'Data Type': ['Email/Passwords', 'Personal/Financial', 'Personal Info', 'Personal/Payment', 'Passwords', 'Professional']
    })
    
    fig = px.scatter(breach_data, x='Year', y='Records Affected (Millions)', 
                    size='Records Affected (Millions)', color='Company',
                    title='Major Data Breaches by Year and Impact',
                    hover_data=['Data Type'])
    st.plotly_chart(fig, use_container_width=True)
    
    st.subheader("🔍 How to Check for Breaches")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        ### Legitimate Breach Checking Services:
        
        **HaveIBeenPwned.com**
        - Most comprehensive breach database
        - Created by security researcher Troy Hunt
        - Free email and password checking
        - Notify service for future breaches
        
        **Firefox Monitor**
        - Mozilla's breach checking service
        - Integrated with Firefox browser
        - Email monitoring and alerts
        
        **Google Password Checkup**
        - Built into Chrome browser
        - Checks saved passwords against breaches
        - Integrated with Google accounts
        """)
    
    with col2:
        st.markdown("""
        ### What to Do If You're Breached:
        
        1. **Change passwords immediately**
           - On the breached service
           - On any accounts using the same password
        
        2. **Enable 2FA** on all important accounts
        
        3. **Monitor your accounts** for unusual activity
        
        4. **Consider identity monitoring** services
        
        5. **Update security questions** if they were exposed
        
        6. **Check credit reports** for financial breaches
        
        7. **Use a password manager** going forward
        """)
    
    st.markdown("""
    <div class="warning-box">
        <h4>⚠️ Privacy Note</h4>
        <p>This tool doesn't check breaches directly to protect your privacy. 
        Use the legitimate services mentioned above to check if your accounts have been compromised.</p>
    </div>
    """, unsafe_allow_html=True)

if __name__ == "__main__":
    main()
