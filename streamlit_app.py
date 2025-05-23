import streamlit as st
import requests
from streamlit_cookies_manager import EncryptedCookieManager
from uuid import uuid4
import firebase_admin
from firebase_admin import credentials, firestore, auth
from streamlit import navigation, Page

jso = {
  "type": "service_account",
  "project_id": "login1-e7ab2",
  "private_key_id": "8a0331707e0946aec4d2e4ad3eccd026bc51d427",
  "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC78gEWIN6k33Fn\nYWRYdt4ouM5MNn9p/Yobj2dqHVxK5dXe5W6YVATyjLd3gLjEYOGxFNLltbHEjmn/\ndfgMO+ue12uEknwxrkTpNb8UCdEEWwUV+NFCCkYueHgMNiO4PKlZeoN26O8o/0Xw\nH6T06Xj8aY05b2kto4EnhgoyZ96PdzErgbmghLdppw//nZ9QtFE/pramrUTmKAPU\n4o3aeWXKVDuph0+UC68ZOjI+yUnq5K7KJSvQdHoQzJ4LSbkZPCcpzuwXDYOSzMs5\nHk51nkJvq/M4oNG6qZwt46HqZm3m9lFSzEw7FO2JTg1RmZT+ul48haCkiOmFApeV\nDB2pwJHrAgMBAAECggEACI34XLB8UdbVy5XUQm6OqB3ZTgDBBesDaUO6ukrB06ro\ndC/PO+G/I+chxq+2OUILo8rF2qzNfZvZ2UXeV3g2vlEh1LPyMTS0cEUBAIF94Qvf\njGN56t6a2SykkjG4qH8iWi9IYpYxpJUR8t8N3BPwbNTFF9MpX2lszIa+WhL+P1ti\nUqstmjmIlYvjMkrwXTAkhsBzmmest6UAfgXGJREY7Q3mIVpwUMB4erONHeJha69A\nOLJO+2h0JCGO7h8O098dyw+mzntunK0IT3BYMIf9EFhWYeJRE/dgB9kOrRt06QA5\n/n0J5oQ1XThAjt6tEM3hdML+L2Q5FvMV33n3zPdraQKBgQD+Ub3WbmvaLiuXzci/\n8ZguPGgRSvY9XvQPkGdEKSwRMMr+aPPifyG8AQOj4C9DpVBBMNvBAh1JBG8ERQQ2\nwYioGqmzIiWzuJp6C7uDbqtVa3dZWWTfzYcmPurRKb6X0rnC+mnUifXb8GbBuvni\n8Ly1QJY1KkIy6e1+VRK9ZqGsPwKBgQC9L/iOtu8sF/+RaQB/lf2x/0yErFyQo/oD\noIsQduyGyo3bkV6A+bo2yqEo5LHxJ5I0colhY+MHzgAjSPnSEzjNkaOPc44JV5wM\nTzp9XvwOtwTooqvbatJOLgq07tCvVcqAjYESYIcBrxPwx9071vwtxx4cO629zMHI\ncgVH+xlfVQKBgFSUkvJR3wS8/jqKcg2EJ/yYknPN3n8iqUDT4cRFfSZqd9iMxy+4\n4FtKaw+Ba7avsDU+LpfOQDcchl+BJJmhW/WsiGvPG4LeDmIwrLhVgh3yk8rfdDEK\nhbwuiKHvpDeSGb3C0pehGmd/WG1t5dWYAuq1BD/CQin0qsutN4JOM865AoGBAJS6\n28tGoaymiTKFu/CRuEpxDHTZFERZxTmIwwsEk1o8b12IYSVALlbY4e3GLOYLV/OH\nf91iq579IjqbKlsu5V8m+dDS5X0OtQ0wVCkvvTTMST2idT0gM4lmxOANR14wMezy\nUeBipoB6ZVDLr29VyhcrDM7hU+t8x3OPv/sguoepAoGAPhth34MAD80Q8C4YKS1U\ncZ1GacrlTAub0xw13U6eJWvPdxAlwcipQzPl7PgpCspdA5sl/jStzNk7KQdrER6r\nxQxS53OqWAJgPM4FCJFSl5hgReQaWbfzOgy68AuX/n/EoJxh+ZFTJuT3xAiXfvW+\nnslXA1iYhs24bqJUkSlMTqE=\n-----END PRIVATE KEY-----\n",
  "client_email": "firebase-adminsdk-fbsvc@login1-e7ab2.iam.gserviceaccount.com",
  "client_id": "109536071117363121755",
  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
  "token_uri": "https://oauth2.googleapis.com/token",
  "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
  "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/firebase-adminsdk-fbsvc%40login1-e7ab2.iam.gserviceaccount.com",
  "universe_domain": "googleapis.com"
}

# === Firebase Configuration ===
SERVICE_ACCOUNT_FILE = jso
FIREBASE_WEB_API_KEY = "AIzaSyCj0UPv444P-C6ggFZ8Q_NXvSSBraHeDG4"
FIREBASE_AUTH_URL = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={FIREBASE_WEB_API_KEY}"
ROLES = ["Registration", "Student", "Teacher", "Admin", None]

# === Initialize Firebase ===
@st.cache_resource
def init_firebase():
    if not firebase_admin._apps:
        cred = credentials.Certificate(SERVICE_ACCOUNT_FILE)
        firebase_admin.initialize_app(cred)
    return firestore.client()

db = init_firebase()
st.session_state.setdefault("db", db)

# === Firebase Authentication ===
@st.cache_data(show_spinner=True)
def verify_user(email: str, password: str, user_type: str):
    try:
        response = requests.post(FIREBASE_AUTH_URL, json={
            "email": email,
            "password": password,
            "returnSecureToken": True
        })
        data = response.json()

        if response.status_code == 200:
            user_id = data.get("localId")
            doc = db.collection(user_type).document(user_id).get()
            if doc.exists:
                return True, "Authentication successful", doc.to_dict(), user_id
            return False, "User data not found", None, None
        return False, data.get("error", {}).get("message", "Authentication failed"), None, None

    except Exception as e:
        return False, f"Authentication failed: {str(e)}", None, None

def register_user(email, password, username, role):
    try:
        user = auth.create_user(email=email, password=password, uid=str(uuid4()))
        db.collection("users").document(user.uid).set({
            "username": username,
            "role": role,
            "email": email,
            "uid": user.uid
        })
        return True, "Registration successful"
    except auth.EmailAlreadyExistsError:
        return False, "Email already exists"
    except Exception as e:
        return False, f"Registration failed: {str(e)}"

# === Cookie Manager ===
cookies = EncryptedCookieManager(
    prefix="my_app/",
    password="8929239608489292396084"
)

if not cookies.ready():
    st.stop()

for key in ["role", "user_id", "email"]:
    st.session_state.setdefault(key, cookies.get(key))

# === Load SVG ===
@st.cache_data
def load_svg(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8") as file:
            return file.read()
    except Exception as e:
        return f"<!-- SVG Load Error: {e} -->"

# === UI Components ===
def login():
    # Apply custom CSS to remove scrollbar and center content
    st.markdown("""
        <style>
            /* Remove scrollbar */
            html, body, [class*="css"]  {
                overflow: hidden;
            }
            
            /* Center the login form */
            .block-container {
                padding-top: 2rem;
                max-width: 500px;
                margin: 0 auto;
            }
            
            /* SVG styling */
            .svg-container {
                text-align: center;
                margin-top: 1rem;
                margin-bottom: 2rem;
            }
            .svg-container svg {
                max-width: 200px;
                width: 100%;
                height: auto;
            }
            
            /* Form styling */
            .stTextInput, .stSelectbox, .stButton {
                width: 100%;
                margin-bottom: 1rem;
            }
            
            /* Adjust spacing */
            .stHeadingContainer {
                text-align: center;
                margin-bottom: 2rem;
            }
        </style>
    """, unsafe_allow_html=True)

    # Load and display SVG logo
    svg_content = load_svg("Logo/bg.svg")
    st.markdown(f"<div class='svg-container'>{svg_content}</div>", unsafe_allow_html=True)

    st.header("Log in")

    with st.form("login_form"):
        email = st.text_input("Email.", value="sshax1015@gmail.com")
        password = st.text_input("Password", type="password", value="123456789")
        role = st.selectbox("Choose your role", [r for r in ROLES if r])

        submitted = st.form_submit_button("Log in")
        if submitted:
            with st.spinner("Authenticating..."):
                success, message, user_data, user_id = verify_user(email, password, role)

                if success:
                    for key, val in [("role", role), ("user_id", user_id), ("email", email)]:
                        st.session_state[key] = val
                        cookies[key] = val
                    cookies.save()
                    st.success("Logged in successfully!")
                    st.rerun()
                else:
                    st.error(f"Login failed: {message}")

def logout():
    for key in ["role", "user_id", "email"]:
        st.session_state[key] = None
        cookies[key] = ""
    cookies.save()
    st.success("Logged out successfully!")
    st.cache_data.clear()
    st.rerun()

def get_pages():
    from streamlit import Page
    return {
        "Student": [
            Page("student/student.py", title="Student", icon="🎓", default=st.session_state.role == "Student"),
            Page("student/Test_ID_Box.py", title="Take test by id Box",icon="📦")],
        

        "Teacher": [
                    Page("teacher/teacher.py", title="Teacher", icon="👩‍🏫", default=st.session_state.role == "Teacher"),
                    Page("teacher/show_box.py", title="Show box", icon="📦"),
                    Page("teacher/Statistic_by_box.py", title="Statistcs Student By Box", icon="📈"),
                    Page("teacher/Table_Statistics.py", title="Statistcs Table", icon="📈") ],
                         
        "Admin": [
                    Page("admin/admin.py", title="Admin", icon="👨‍💼", default=st.session_state.role == "Admin"),
                    Page("admin/rasch_model.py", title="Rasch Model", icon="📈")
                   
                   ],
        "Registration": [Page("registration/registration.py", title="Registration", icon="📝", default=st.session_state.role == "Registration")],
        "Account": [
            Page("settings.py", title="Settings", icon="⚙️"),
            Page(logout, title="Log out", icon="🚪")
        ]
    }

def main():
    

    if not st.session_state.role:
        navigation([Page(login, title="Login")]).run()
        return

    pages = get_pages()
    user_pages = {
        section: items for section, items in pages.items()
        if section == st.session_state.role or section == "Account"
    }

    if user_pages:
        navigation(user_pages).run()
    else:
        st.error("No pages available for your role.")
        if st.button("Logout"):
            logout()

if __name__ == "__main__":
    main()
