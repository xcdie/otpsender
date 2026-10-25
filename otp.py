from datetime import datetime, timedelta
from email.message import EmailMessage
import os
import random
import smtplib
from fastapi import BackgroundTasks, FastAPI, Form, Request
from fastapi.responses import RedirectResponse
from jinja2 import DictLoader
from sqlmodel import Field, Session, SQLModel, create_engine, select
from starlette.middleware.sessions import SessionMiddleware
from starlette.templating import Jinja2Templates

# 1. Database Setup
DATABASE_URL = "sqlite:///./auth_background.db"
engine = create_engine(
    DATABASE_URL, connect_args={"check_same_thread": False}
)


class OTPToken(SQLModel, table=True):
  id: int | None = Field(default=None, primary_key=True)
  email: str = Field(index=True, unique=True)
  otp: str
  expires_at: datetime


SQLModel.metadata.create_all(engine)


app = FastAPI()
app.add_middleware(
    SessionMiddleware, secret_key="096798037080875"
)


templates_dict = {
    "layout.html": """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>FastAPI Background Email OTP</title>
        <script src="https://cdn.tailwindcss.com"></script>
    </head>
    <body class="bg-gray-50 flex items-center justify-center h-screen">
        <div class="bg-white p-8 rounded-xl shadow-md w-full max-w-md">
            {% block content %}{% endblock %}
        </div>
    </body>
    </html>
    """,
    "index.html": """
    {% extends "layout.html" %}
    {% block content %}
    {% if user_email %}
        <h1 class="text-2xl font-bold mb-4 text-green-600">Welcome, {{ user_email }}! 🎉</h1>
        <p class="text-gray-600 mb-6">Authenticated with background SMTP task dispatch.</p>
        <a href="/logout" class="block text-center bg-red-600 text-white py-2 rounded-lg hover:bg-red-700 transition">Log Out</a>
    {% else %}
        <h1 class="text-2xl font-bold mb-4 text-gray-800">Email OTP Login</h1>
        <form action="/send-otp" method="POST" class="space-y-4">
            <div>
                <label class="block text-sm font-medium text-gray-700 mb-1">Email Address</label>
                <input type="email" name="email" required class="w-full px-4 py-2 border rounded-lg focus:ring-2 focus:ring-blue-500 outline-none">
            </div>
            <button type="submit" class="w-full bg-blue-600 text-white py-2 rounded-lg font-medium hover:bg-blue-700 transition">Send OTP Code</button>
        </form>
    {% endif %}
    {% endblock %}
    """,
    "verify.html": """
    {% extends "layout.html" %}
    {% block content %}
    <h1 class="text-2xl font-bold mb-2 text-gray-800">Enter Verification Code</h1>
    <p class="text-sm text-gray-500 mb-4">Code sent asynchronously to <b>{{ email }}</b>.</p>
    <form action="/verify-otp" method="POST" class="space-y-4">
        <div>
            <input type="text" name="otp" maxlength="6" placeholder="123456" required class="w-full px-4 py-2 text-center text-2xl tracking-widest border rounded-lg focus:ring-2 focus:ring-blue-500 outline-none">
        </div>
        <button type="submit" class="w-full bg-green-600 text-white py-2 rounded-lg font-medium hover:bg-green-700 transition">Verify & Sign In</button>
    </form>
    {% endblock %}:
    """,
}

templates = Jinja2Templates(env=None)
templates.env.loader = DictLoader(templates_dict)


def send_email_smtp(email: str, otp_code: str):
  """Sends an email via SMTP.

  FastAPI automatically runs this function in a separate thread pool so it
  doesn't block the event loop.
  """

  smtp_server = os.getenv("SMTP_SERVER", "smtp.gmail.com")
  smtp_port = int(os.getenv("SMTP_PORT", 587))
  sender_email = os.getenv("SMTP_SENDER", "jamlickmarsh400@gmail.com")
  sender_password = os.getenv("SMTP_PASSWORD", "678499")

  msg = EmailMessage()
  msg.set_content(
      f"Your login verification code is: {otp_code}\nThis code expires in 1"
      " minute."
  )
  msg["Subject"] = "Your One-Time Verification Code"
  msg["From"] = sender_email
  msg["To"] = email

  try:
    with smtplib.SMTP(smtp_server, smtp_port) as server:
      server.starttls()
      server.login(sender_email, sender_password)
      server.send_message(msg)
    print(f"[BACKGROUND TASK] Email successfully sent to {email}")
  except Exception as e:
    # In production, log this error using a structured logger
    print(f"[BACKGROUND TASK ERROR] Failed to send email to {email}: {e}")


# 5. Application Routes
@app.get("/")
def index(request: Request):
  user_email = request.session.get("user_email")
  return templates.TemplateResponse(
      "index.html", {"request": request, "user_email": user_email}
  )


@app.post("/send-otp")
def send_otp(
    request: Request, background_tasks: BackgroundTasks, email: str = Form(...)
):
  otp_code = f"{random.randint(0, 999999):06d}"
  expires = datetime.utcnow() + timedelta(minutes=5)

  with Session(engine) as db:
    token_entry = db.exec(select(OTPToken).where(OTPToken.email == email)).first()
    if token_entry:
      token_entry.otp = otp_code
      token_entry.expires_at = expires
      db.add(token_entry)
    else:
      token_entry = OTPToken(email=email, otp=otp_code, expires_at=expires)
      db.add(token_entry)
    db.commit()

  # Add email dispatch task to FastAPI background queue
  background_tasks.add_task(send_email_smtp, email, otp_code)

  request.session["pending_email"] = email
  return RedirectResponse(url="/verify", status_code=303)


@app.get("/verify")
def verify_page(request: Request):
  email = request.session.get("pending_email", "")
  return templates.TemplateResponse(
      "verify.html", {"request": request, "email": email}
  )


@app.post("/verify-otp")
def verify_otp(request: Request, otp: str = Form(...)):
  email = request.session.get("pending_email")
  if not email:
    return RedirectResponse(url="/", status_code=303)

  with Session(engine) as db:
    token_entry = db.exec(select(OTPToken).where(OTPToken.email == email)).first()

    if token_entry and token_entry.otp == otp:
      if datetime.utcnow() <= token_entry.expires_at:
        db.delete(token_entry)
        db.commit()

        request.session.pop("pending_email", None)
        request.session["user_email"] = email
        return RedirectResponse(url="/", status_code=303)

  return RedirectResponse(url="/verify", status_code=303)


@app.get("/logout")
def logout(request: Request):
  request.session.clear()
  return RedirectResponse(url="/", status_code=303)


if __name__ == "__main__":
  import uvicorn

  uvicorn.run("app_bg:app", host="127.0.0.1", port=8000, reload=True)