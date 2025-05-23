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
  "private_key_id": "ef0e00e14a4ebf859f7298cb127019b6c1620004",
  "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCg5KUEsAGtKfb/\n7s8dHB5fyKiKAr0giY2g9NKACbGTHVtDV77VQijBL8cCYEcbGCnRZJiAWyQZQXq+\n1BKbVyOg5lHras5NFCTWFZ9y9aNKbijuN93vHMdCquiENyA23gRwFFaIeN1Dl2gt\n8qGY9V5ZS3O5LyaC2dE5BvCLHfyBGYysGfuuoiVJb7k6nSQsJm07uz6Cw3WVOCO6\naR6kZflpujaSOiJ5oX+TFIrd31lGzNpsLEYj2dQzvwaJY8sY6Bbj3gHPYZIxoGBK\nAqG8apwSe61RDoglhooK8kF+OJer0onSgw8K5dFnI4Mb7pj5tr/H6FoLHtq1TRHG\nheIX9TmDAgMBAAECggEATNRCFJXzhvwWDaq8zhrCSlzoVlbudx4YOncOGcQHPsfy\n75pz7yQTkAS/lFvjOIX2Wh4eUJS1DTZeZcehRvp6cffpwHAVKWtoF67loCC6I+2s\nr+yPlwH4CNbSB2jHgkvMdLTRiYOlrQQc5GwLTJ5Gun80OIbSbgOTTBcLQHNGQ2Ls\nySed7TwCXuCjYKwSRzStoOD5gh5gpOhY/OnMwG9i2OfBqLLfJZfs7EQVr4DhZHzo\ng1Q6lAzePPPelRk73pTOoJjfcq2rk54lPKyo/qQLy5QZq6O8orzW0xxMgHXRWk1D\nUUx2SL4x+EhoKeDOuO213Rmo/Xt+i8H23rhOPK4QgQKBgQDXGaTZMLmWtAUsSDtK\n8WxeRh+UddwgJkzFyrDTPkITw6BE63eu2Yj5ymgwCvSirK3X4ypsuqEqNLz9rEXj\nWV1UlKGTry85oILA9zJfHYEOPlqxO0DkkUEcDwf2atoxi1xREDQ5+I1HrFBU6ReX\nVXTkfwo99zHsEse14/SHdYg6QwKBgQC/fGJPtpsmmP2rdNx6iGxB+ZIOuT7W6FBe\ndTLDatF0WbOKEdnGVO9yCx8CV4FiuBMbkJFfOp1vDyFaMRaZwFaRSDrNTFHe1asR\nV0OvlC32LbgvlO/axoKfCo6J9YAJm4c3E9V1JhKXXtfr3OP5rzcX1g/m5aVjQhi0\nQBc/jMUvwQKBgQDEYdtJl9y5JJ5ccY4AvC5OXANVDc3tZEpPguCx3HODi+V1Ru28\nK0uNkyhQRJBZPQJyyinfnvyphgDOMUyVZu9420IxjY22NT9rYcURZeR/1poCmbCD\nfcJOFcMVTTTsaunb8Mld6/lA6Kdm/nDVb+YK/5mgPWHMwNCo1fhY/Atl9QKBgCA3\nOwsSO9QolTUNejKbVStcY7habjoV57+clCfQhuC+Xrhx/GOj0o0rVdI9CqWjNoPC\ntNKCuA4BS6ky7Qx9EZNrxYjYuEV3SUqnldmqYnkyg/RtaFU0ZLGBQy3uwdXb9snL\nanRFLYeOC2HBThGp6uj1uMMuC79BVYqt5btpYZuBAoGAHyfGZH32fjlibZTBO2qT\nfwYT+KpSAPv5XFwDEp/bNYiRERu3+MtrN9rFN1T4D3tguHzS8fDhp/NI0xDBQOCn\n9DBDs9K9tq5HoH918UZouovKhAuTbPITu8iCBcf6bPMmKTSUW8RBSl5aHoy5+e3K\nsJDuwpGmZ69lSaB3NDS5b8s=\n-----END PRIVATE KEY-----\n",
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
        email = st.text_input("Email", value="sshax1015@gmail.com")
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
