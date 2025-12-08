# app.py : backend for customers, agents, staff

from flask import (
    Flask, render_template, request,
    redirect, url_for, session, flash
)
import pymysql
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash

from config import DB_CONFIG, SECRET_KEY

app = Flask(__name__)
app.secret_key = SECRET_KEY

DB_CONFIG = {
    'host': '127.0.0.1',
    'user': 'root',
    'password': '',         
    'port': 3306,
    'database': 'air_reservation',
    'charset': 'utf8mb4'
}



# DB Connection

def get_db_connection():
    return pymysql.connect(
        host=DB_CONFIG['host'],
        user=DB_CONFIG['user'],
        password=DB_CONFIG['password'],
        port=DB_CONFIG['port'],
        db=DB_CONFIG['database'],
        charset=DB_CONFIG['charset'],
        cursorclass=pymysql.cursors.DictCursor,
        autocommit=True
    )


# Login require decorator
def login_required(role=None):
    from functools import wraps

    def decorator(view_func):
        @wraps(view_func)
        def wrapped(*args, **kwargs):
            if "user_type" not in session:
                flash("Please log in first.")
                return redirect(url_for("login"))
            if role is not None and session.get("user_type") != role:
                flash("You are not authorized to view that page.")
                return redirect(url_for("home"))
            return view_func(*args, **kwargs)
        return wrapped

    return decorator



#Public Routes
@app.route("/")
def home():
    return render_template("home.html")


@app.route("/search", methods=["GET", "POST"])
def public_search_page():
    """Public search for upcoming flights."""
    flights = []
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            sql = "SELECT * FROM flight WHERE status = 'upcoming'"
            params = []

            if request.method == "POST":
                origin = request.form.get("origin")
                destination = request.form.get("destination")
                date = request.form.get("date")

                if origin:
                    sql += " AND departure_airport = %s"
                    params.append(origin)
                if destination:
                    sql += " AND arrival_airport = %s"
                    params.append(destination)
                if date:
                    sql += " AND DATE(departure_time) = %s"
                    params.append(date)

            cur.execute(sql, params)
            flights = cur.fetchall()
    finally:
        conn.close()

    return render_template("search_page.html", flights=flights)


# Registration

@app.route("/register")
def register():
    return render_template("register.html")


# Customer Registration
@app.route("/register/customer", methods=["GET", "POST"])
def register_customer():
    if request.method == "POST":
        form = request.form

        required = ["email", "name", "password"]
        if any(not form.get(f) for f in required):
            flash("Email, name, and password are required.")
            return redirect(url_for("register_customer"))

        conn = get_db_connection()
        try:
            with conn.cursor() as cur:
                # check existing
                cur.execute("SELECT email FROM customer WHERE email = %s", (form["email"],))
                if cur.fetchone():
                    flash("Customer already exists.")
                    return redirect(url_for("register_customer"))

                hashed = generate_password_hash(form["password"])

                cur.execute("""
                    INSERT INTO customer
                    (email, name, password_hash,
                     building_number, street, city, state,
                     phone_number, passport_number,
                     passport_expiration, passport_country,
                     date_of_birth)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                """, (
                    form["email"], form["name"], hashed,
                    form.get("building_number"), form.get("street"),
                    form.get("city"), form.get("state"),
                    form.get("phone_number"), form.get("passport_number"),
                    form.get("passport_expiration"), form.get("passport_country"),
                    form.get("date_of_birth")
                ))

            flash("Customer registered. Please log in.")
            return redirect(url_for("login"))
        finally:
            conn.close()

    return render_template("register_customer.html")


# Agent Registration
@app.route("/register/agent", methods=["GET", "POST"])
def register_agent():
    if request.method == "POST":
        email = request.form.get("email")
        pw = request.form.get("password")

        if not email or not pw:
            flash("Email and password are required.")
            return redirect(url_for("register_agent"))

        conn = get_db_connection()
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT email FROM booking_agent WHERE email=%s", (email,))
                if cur.fetchone():
                    flash("Booking agent already exists.")
                    return redirect(url_for("register_agent"))

                hashed = generate_password_hash(pw)

                cur.execute("""
                    INSERT INTO booking_agent (email, password_hash)
                    VALUES (%s,%s)
                """, (email, hashed))

            flash("Booking agent registered. Please log in.")
            return redirect(url_for("login"))
        finally:
            conn.close()

    return render_template("register_agent.html")


# Staff Registration
@app.route("/register/staff", methods=["GET", "POST"])
def register_staff():
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT airline_name FROM airline")
            airlines = [row["airline_name"] for row in cur.fetchall()]
    finally:
        conn.close()

    if request.method == "POST":
        form = request.form
        username = form.get("username")
        pw = form.get("password")
        airline_name = form.get("airline_name")
        reg_code = form.get("reg_code")

        # required fields
        if not username or not pw or not airline_name:
            flash("Username, password, and airline are required.")
            return redirect(url_for("register_staff"))

        # validate airline exists
        if airline_name not in airlines:
            flash("Selected airline does not exist. Please choose from the list.")
            return redirect(url_for("register_staff"))
        conn = get_db_connection()
        try:
            with conn.cursor() as cur:

                #validate registration
                cur.execute(
                    """
                    SELECT 1
                    FROM airline
                    WHERE airline_name = %s
                      AND staff_reg_hash = SHA2(%s, 256)
                    """,
                    (airline_name, reg_code),
                )

                if not cur.fetchone():
                    flash("Invalid registration code.")
                    return redirect(url_for("register_staff"))

                # check if username already exists
                cur.execute(
                    "SELECT username FROM airline_staff WHERE username=%s",
                    (username,)
                )
                if cur.fetchone():
                    flash("Staff user already exists.")
                    return redirect(url_for("register_staff"))

                # insert new staff member
                hashed_pw = generate_password_hash(pw)
                role = form.get("role", "admin")  # default to admin if not provided

                cur.execute(
                    """
                    INSERT INTO airline_staff
                    (username, password_hash, first_name, last_name, date_of_birth,
                     airline_name, role)
                    VALUES (%s,%s,%s,%s,%s,%s,%s)
                    """,
                    (
                        username,
                        hashed_pw,
                        form.get("first_name"),
                        form.get("last_name"),
                        form.get("date_of_birth"),
                        airline_name,
                        role,
                    )
                )

                flash("Staff registered successfully. Please log in.")
                return redirect(url_for("login"))

        finally:
            conn.close()

    return render_template("register_staff.html", airlines=airlines)
        

# Login
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user_type = request.form.get("user_type")        # customer / agent / staff
        identifier = request.form.get("identifier")      # email or username
        password = request.form.get("password")

        conn = get_db_connection()
        try:
            with conn.cursor() as cur:

                # ---------- CUSTOMER ----------
                if user_type == "customer":
                    cur.execute("SELECT * FROM customer WHERE email=%s", (identifier,))
                    user = cur.fetchone()
                    if user and check_password_hash(user["password_hash"], password):
                        session.clear()
                        session["user_type"] = "customer"
                        session["user_id"] = user["email"]
                        return redirect(url_for("customer_dashboard"))

                # ---------- AGENT ----------
                elif user_type == "agent":
                    cur.execute("SELECT * FROM booking_agent WHERE email=%s", (identifier,))
                    user = cur.fetchone()
                    if user and check_password_hash(user["password_hash"], password):
                        session.clear()
                        session["user_type"] = "agent"
                        session["user_id"] = user["email"]
                        return redirect(url_for("agent_dashboard"))

                # ---------- STAFF ----------
                elif user_type == "staff":
                    cur.execute("""
                        SELECT username, password_hash, airline_name, role
                        FROM airline_staff
                        WHERE username=%s
                    """, (identifier,))
                    user = cur.fetchone()
                    if user and check_password_hash(user["password_hash"], password):
                        session.clear()
                        session["user_type"] = "staff"
                        session["user_id"] = user["username"]
                        session["airline_name"] = user["airline_name"]
                        session["staff_role"] = user["role"]
                        return redirect(url_for("staff_dashboard"))

        finally:
            conn.close()

        flash("Invalid credentials.")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out.")
    return redirect(url_for("home"))


# Customer Features
# Customer Dashboard
@app.route("/customer", methods=["GET", "POST"])
@login_required("customer")
def customer_dashboard():
    email = session["user_id"]
    conn = get_db_connection()

    flights = []
    total_last_12 = 0
    default_month_labels = []
    default_month_amounts = []

    custom_total = None
    custom_month_labels = []
    custom_month_amounts = []

    def last_n_month_labels(n, today):
        labels = []
        year = today.year
        month = today.month
        for k in range(n - 1, -1, -1):
            m = month - k
            y = year
            while m <= 0:
                m += 12
                y -= 1
            labels.append(f"{y:04d}-{m:02d}")
        return labels

    try:
        with conn.cursor() as cur:

            # flight filtering
            base_query = """
                SELECT f.*
                FROM ticket t
                JOIN purchases p ON p.ticket_id = t.ticket_id
                JOIN flight f ON f.airline_name = t.airline_name
                              AND f.flight_num = t.flight_num
                WHERE p.customer_email = %s
            """
            params = [email]

            filtering = request.method == "POST" and request.form.get("form_type") == "flight_filter"

            if filtering:
                start = request.form.get("filter_start")
                end = request.form.get("filter_end")
                origin = request.form.get("filter_origin")
                destination = request.form.get("filter_destination")

                if start:
                    base_query += " AND DATE(f.departure_time) >= %s"
                    params.append(start)
                if end:
                    base_query += " AND DATE(f.departure_time) <= %s"
                    params.append(end)
                if origin:
                    base_query += " AND f.departure_airport = %s"
                    params.append(origin)
                if destination:
                    base_query += " AND f.arrival_airport = %s"
                    params.append(destination)
            else:
                base_query += " AND f.status = 'upcoming'"  # Default view: ONLY upcoming flights

            base_query += " ORDER BY f.departure_time"

            cur.execute(base_query, params)
            flights = cur.fetchall()


            # deafult spending
            today = datetime.today().date()
            year_start = today - timedelta(days=365)
            six_months_start = today - timedelta(days=180)

            cur.execute("""
                SELECT COALESCE(SUM(purchase_price), 0) AS total
                FROM purchases
                WHERE customer_email = %s
                  AND purchase_date BETWEEN %s AND %s
            """, (email, year_start, today))
            total_last_12 = cur.fetchone()["total"]

            cur.execute("""
                SELECT DATE_FORMAT(purchase_date, '%%Y-%%m') AS month,
                       SUM(purchase_price) AS total
                FROM purchases
                WHERE customer_email = %s
                  AND purchase_date BETWEEN %s AND %s
                GROUP BY month
                ORDER BY month
            """, (email, six_months_start, today))
            rows = cur.fetchall()

            month_map = {row["month"]: float(row["total"]) for row in rows}

            default_month_labels = last_n_month_labels(6, today)
            default_month_amounts = [month_map.get(m, 0) for m in default_month_labels]


            # custome spending
            if request.method == "POST" and request.form.get("form_type") == "custom_spending":
                start = request.form.get("start_date")
                end = request.form.get("end_date")

                cur.execute("""
                    SELECT COALESCE(SUM(purchase_price), 0) AS total
                    FROM purchases
                    WHERE customer_email = %s
                      AND purchase_date BETWEEN %s AND %s
                """, (email, start, end))
                custom_total = cur.fetchone()["total"]

                cur.execute("""
                    SELECT DATE_FORMAT(purchase_date, '%%Y-%%m') AS month,
                           SUM(purchase_price) AS total
                    FROM purchases
                    WHERE customer_email = %s
                      AND purchase_date BETWEEN %s AND %s
                    GROUP BY month
                    ORDER BY month
                """, (email, start, end))
                c_rows = cur.fetchall()

                custom_month_labels = [r["month"] for r in c_rows]
                custom_month_amounts = [float(r["total"]) for r in c_rows]

    finally:
        conn.close()

    return render_template(
        "customer_dashboard.html",
        flights=flights,
        total_last_12=total_last_12,
        default_month_labels=default_month_labels,
        default_month_amounts=default_month_amounts,
        custom_total=custom_total,
        custom_month_labels=custom_month_labels,
        custom_month_amounts=custom_month_amounts,
    )



# Search flights (customer view)
@app.route("/customer/search_flights", methods=["POST"])
@login_required("customer")
def customer_search_flights():
    origin = request.form.get("origin")
    destination = request.form.get("destination")
    date_str = request.form.get("date")

    conn = get_db_connection()
    flights = []

    try:
        with conn.cursor() as cur:
            sql = "SELECT * FROM flight WHERE status = 'upcoming'"
            params = []

            if origin:
                sql += " AND departure_airport = %s"
                params.append(origin)
            if destination:
                sql += " AND arrival_airport = %s"
                params.append(destination)
            if date_str:
                sql += " AND DATE(departure_time) = %s"
                params.append(date_str)

            cur.execute(sql, params)
            flights = cur.fetchall()
    finally:
        conn.close()

    return render_template("customer_search_results.html", flights=flights)


# Purchase (customer buys)
@app.route("/customer/purchase/<airline_name>/<int:flight_num>", methods=["GET", "POST"])
@login_required("customer")
def customer_purchase(airline_name, flight_num):
    customer_email = session["user_id"]
    conn = get_db_connection()

    if request.method == "POST":
        seat_class_id = int(request.form.get("seat_class_id"))
        today = datetime.today().date()

        try:
            with conn.cursor() as cur:
                # flight info
                cur.execute("""
                    SELECT airplane_id, base_price
                    FROM flight
                    WHERE airline_name = %s AND flight_num = %s
                """, (airline_name, flight_num))
                flight = cur.fetchone()
                if not flight:
                    flash("Flight not found.")
                    return redirect(url_for("customer_dashboard"))

                airplane_id = flight["airplane_id"]
                base_price = flight["base_price"]

                # seat class data
                cur.execute("""
                    SELECT seat_capacity
                    FROM seat_class
                    WHERE airline_name=%s
                      AND airplane_id=%s
                      AND seat_class_id=%s
                """, (airline_name, airplane_id, seat_class_id))
                sc = cur.fetchone()
                if not sc:
                    flash("Seat class not found.")
                    return redirect(url_for("customer_dashboard"))

                capacity = sc["seat_capacity"]

                # seats sold in that class
                cur.execute("""
                    SELECT COUNT(*) AS sold
                    FROM ticket
                    WHERE airline_name=%s
                      AND flight_num=%s
                      AND airplane_id=%s
                      AND seat_class_id=%s
                """, (airline_name, flight_num, airplane_id, seat_class_id))
                sold = cur.fetchone()["sold"]

                if sold >= capacity:
                    flash("Sorry, no seats left in this class.")
                    return redirect(url_for("customer_dashboard"))

                # pricing
                multiplier = 1.0
                if seat_class_id == 2:
                    multiplier = 1.5
                elif seat_class_id == 3:
                    multiplier = 2.0
                purchase_price = float(base_price) * multiplier

                # next ticket id
                cur.execute("SELECT COALESCE(MAX(ticket_id),0) + 1 AS next_id FROM ticket")
                ticket_id = cur.fetchone()["next_id"]

                cur.execute("""
                    INSERT INTO ticket (ticket_id, airline_name, flight_num, airplane_id, seat_class_id)
                    VALUES (%s,%s,%s,%s,%s)
                """, (ticket_id, airline_name, flight_num, airplane_id, seat_class_id))

                cur.execute("""
                    INSERT INTO purchases (ticket_id, customer_email, purchase_date, purchase_price)
                    VALUES (%s,%s,%s,%s)
                """, (ticket_id, customer_email, today, purchase_price))

                flash("Your ticket has been purchased!")
                return redirect(url_for("customer_dashboard"))
        finally:
            conn.close()

    #GET → show seat classes
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT airplane_id
                FROM flight
                WHERE airline_name=%s AND flight_num=%s
            """, (airline_name, flight_num))
            flight = cur.fetchone()
            if not flight:
                flash("Flight not found.")
                return redirect(url_for("customer_dashboard"))

            airplane_id = flight["airplane_id"]
            cur.execute("""
                SELECT seat_class_id, seat_capacity
                FROM seat_class
                WHERE airline_name=%s AND airplane_id=%s
            """, (airline_name, airplane_id))
            seat_classes = cur.fetchall()
    finally:
        conn.close()

    return render_template(
        "customer_purchase.html",
        airline_name=airline_name,
        flight_num=flight_num,
        seat_classes=seat_classes
    )


# View all purchased flights
@app.route("/customer/purchased_flights")
@login_required("customer")
def customer_purchased_flights():
    """Uses your customer_purchased_flights.html template."""
    email = session["user_id"]
    conn = get_db_connection()
    flights = []
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT f.*
                FROM ticket t
                JOIN purchases p ON p.ticket_id = t.ticket_id
                JOIN flight f ON f.airline_name = t.airline_name
                              AND f.flight_num = t.flight_num
                WHERE p.customer_email = %s
                ORDER BY f.departure_time DESC
            """, (email,))
            flights = cur.fetchall()
    finally:
        conn.close()

    return render_template("customer_purchased_flights.html", flights=flights)


# Agent Features
# Agent Dashboard
@app.route("/agent")
@login_required("agent")
def agent_dashboard():
    email = session["user_id"]
    conn = get_db_connection()

    commission_summary = {}
    top_customers_by_tickets = []
    top_customers_by_commission = []

    try:
        with conn.cursor() as cur:
            # Last 30 days commission
            end = datetime.today().date()
            start = end - timedelta(days=30)

            cur.execute("""
                SELECT COALESCE(SUM(purchase_price * 0.1),0) AS total_commission,
                       COALESCE(AVG(purchase_price * 0.1),0) AS avg_commission,
                       COUNT(*) AS num_tickets
                FROM purchases
                WHERE booking_agent_email=%s
                  AND purchase_date BETWEEN %s AND %s
            """, (email, start, end))
            commission_summary = cur.fetchone()

            # Top customers by tickets (last 6 months)
            six_start = end - timedelta(days=180)
            cur.execute("""
                SELECT customer_email, COUNT(*) AS num_tickets
                FROM purchases
                WHERE booking_agent_email=%s
                  AND purchase_date >= %s
                GROUP BY customer_email
                ORDER BY num_tickets DESC
                LIMIT 5
            """, (email, six_start))
            top_customers_by_tickets = cur.fetchall()

            # Top customers by commission (last 12 months)
            year_start = end - timedelta(days=365)
            cur.execute("""
                SELECT customer_email,
                       SUM(purchase_price * 0.1) AS total_commission
                FROM purchases
                WHERE booking_agent_email=%s
                  AND purchase_date >= %s
                GROUP BY customer_email
                ORDER BY total_commission DESC
                LIMIT 5
            """, (email, year_start))
            top_customers_by_commission = cur.fetchall()

    finally:
        conn.close()

    return render_template(
        "agent_dashboard.html",
        commission_summary=commission_summary,
        top_customers_by_tickets=top_customers_by_tickets,
        top_customers_by_commission=top_customers_by_commission
    )

# Agent serach page for flights to sell
@app.route("/agent/search", methods=["GET", "POST"])
@login_required("agent")
def agent_search():
    email = session["user_id"]
    conn = get_db_connection()

    flights = []

    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT airline_name
                FROM agent_airline_authorization
                WHERE agent_email = %s
            """, (email,))
            authorized_airlines = [row["airline_name"] for row in cur.fetchall()]

            if not authorized_airlines:
                return render_template("agent_search_page.html", flights=[])

            sql = """
                SELECT *
                FROM flight
                WHERE airline_name IN %s
                  AND status = 'upcoming'
            """
            params = [tuple(authorized_airlines)]

            if request.method == "POST":
                origin = request.form.get("origin")
                destination = request.form.get("destination")
                date_str = request.form.get("date")

                if origin:
                    sql += " AND departure_airport = %s"
                    params.append(origin)
                if destination:
                    sql += " AND arrival_airport = %s"
                    params.append(destination)
                if date_str:
                    sql += " AND DATE(departure_time) = %s"
                    params.append(date_str)

            # ALWAYS execute the query
            cur.execute(sql, params)
            flights = cur.fetchall()

    finally:
        conn.close()

    return render_template("agent_search_page.html", flights=flights)


# Agent purchase page
@app.route("/agent/purchase/<airline_name>/<int:flight_num>", methods=["GET", "POST"])
@login_required("agent")
def agent_purchase(airline_name, flight_num):
    agent_email = session["user_id"]
    conn = get_db_connection()

    if request.method == "POST":
        customer_email = request.form.get("customer_email")
        seat_class_id = int(request.form.get("seat_class_id"))
        today = datetime.today().date()

        try:
            with conn.cursor() as cur:

                # Check authorization
                cur.execute("""
                    SELECT 1 FROM agent_airline_authorization
                    WHERE agent_email=%s AND airline_name=%s
                """, (agent_email, airline_name))
                if not cur.fetchone():
                    flash("Not authorized for this airline.")
                    return redirect(url_for("agent_search"))

                # Flight info
                cur.execute("""
                    SELECT airplane_id, base_price
                    FROM flight
                    WHERE airline_name=%s AND flight_num=%s
                """, (airline_name, flight_num))
                f = cur.fetchone()
                airplane_id = f["airplane_id"]
                base_price = float(f["base_price"])

                # Seat class info
                cur.execute("""
                    SELECT seat_capacity FROM seat_class
                    WHERE airline_name=%s AND airplane_id=%s AND seat_class_id=%s
                """, (airline_name, airplane_id, seat_class_id))
                cap = cur.fetchone()["seat_capacity"]

                cur.execute("""
                    SELECT COUNT(*) AS sold
                    FROM ticket
                    WHERE airline_name=%s AND flight_num=%s
                      AND airplane_id=%s AND seat_class_id=%s
                """, (airline_name, flight_num, airplane_id, seat_class_id))
                sold = cur.fetchone()["sold"]

                if sold >= cap:
                    flash("No seats left in this class.")
                    return redirect(url_for("agent_search"))

                # Pricing
                multiplier = {1: 1.0, 2: 1.5, 3: 2.0}[seat_class_id]
                price = base_price * multiplier

                # Create ticket
                cur.execute("SELECT COALESCE(MAX(ticket_id),0)+1 AS next FROM ticket")
                ticket_id = cur.fetchone()["next"]

                cur.execute("""
                    INSERT INTO ticket
                    (ticket_id, airline_name, flight_num, airplane_id, seat_class_id)
                    VALUES (%s,%s,%s,%s,%s)
                """, (ticket_id, airline_name, flight_num, airplane_id, seat_class_id))

                cur.execute("""
                    INSERT INTO purchases
                    (ticket_id, customer_email, booking_agent_email, purchase_date, purchase_price)
                    VALUES (%s,%s,%s,%s,%s)
                """, (ticket_id, customer_email, agent_email, today, price))

                flash("Ticket purchased!")
                return redirect(url_for("agent_dashboard"))

        finally:
            conn.close()

    # GET → show seat classes
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT airplane_id FROM flight
                WHERE airline_name=%s AND flight_num=%s
            """, (airline_name, flight_num))
            f = cur.fetchone()
            airplane_id = f["airplane_id"]

            cur.execute("""
                SELECT seat_class_id, seat_capacity
                FROM seat_class
                WHERE airline_name=%s AND airplane_id=%s
            """, (airline_name, airplane_id))
            seat_classes = cur.fetchall()
    finally:
        conn.close()

    return render_template("purchase_agent.html",
                           airline_name=airline_name,
                           flight_num=flight_num,
                           seat_classes=seat_classes)


# View bookings made as an agent
@app.route("/agent/bookings", methods=["GET", "POST"])
@login_required("agent")
def agent_view_bookings():
    agent_email = session["user_id"]
    conn = get_db_connection()
    flights = []

    try:
        with conn.cursor() as cur:
            sql = """
                SELECT f.*, p.customer_email
                FROM purchases p
                JOIN ticket t ON p.ticket_id = t.ticket_id
                JOIN flight f ON f.airline_name = t.airline_name
                              AND f.flight_num = t.flight_num
                WHERE p.booking_agent_email = %s
            """
            params = [agent_email]

            customer = request.form.get("customer_email")
            origin = request.form.get("origin")
            destination = request.form.get("destination")
            start = request.form.get("start_date")

            if customer:
                sql += " AND p.customer_email = %s"
                params.append(customer)
            if origin:
                sql += " AND f.departure_airport = %s"
                params.append(origin)
            if destination:
                sql += " AND f.arrival_airport = %s"
                params.append(destination)
            if start:
                sql += " AND DATE(f.departure_time) >= %s"
                params.append(start)

            sql += " ORDER BY f.departure_time DESC"

            cur.execute(sql, params)
            flights = cur.fetchall()

    finally:
        conn.close()

    return render_template("agent_view_bookings.html", flights=flights)

# Staff features
# Staff Dashboard
@app.route("/staff")
@login_required("staff")
def staff_dashboard():
    username = session["user_id"]
    airline_name = session.get("airline_name")
    role = session.get("staff_role", "staff")

    conn = get_db_connection()
    flights = []
    stats = {}

    try:
        with conn.cursor() as cur:
            start = datetime.today().date()
            end = start + timedelta(days=30)

            cur.execute("""
                SELECT *
                FROM flight
                WHERE airline_name = %s
                  AND DATE(departure_time) BETWEEN %s AND %s
                ORDER BY departure_time
            """, (airline_name, start, end))
            flights = cur.fetchall()

            year_start = start - timedelta(days=365)
            cur.execute("""
                SELECT DATE_FORMAT(p.purchase_date, '%%Y-%%m') AS month,
                       COUNT(*) AS num_tickets
                FROM purchases p
                JOIN ticket t ON p.ticket_id = t.ticket_id
                WHERE t.airline_name = %s
                  AND p.purchase_date >= %s
                GROUP BY month
                ORDER BY month
            """, (airline_name, year_start))
            stats["tickets_per_month"] = cur.fetchall()
    finally:
        conn.close()

    is_admin = role in ("admin", "both")
    is_operator = role in ("operator", "both")

    return render_template(
        "staff_dashboard.html",
        flights=flights,
        stats=stats,
        role=role,
        airline_name=airline_name,
        is_admin=is_admin,
        is_operator=is_operator
    )


# Passenger list for a flight
@app.route("/staff/passengers/<airline>/<int:flight_num>")
@login_required("staff")
def staff_passengers(airline, flight_num):
    conn = get_db_connection()
    passengers = []
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT c.name, c.email
                FROM ticket t
                JOIN purchases p ON p.ticket_id = t.ticket_id
                JOIN customer c ON c.email = p.customer_email
                WHERE t.airline_name=%s AND t.flight_num=%s
            """, (airline, flight_num))
            passengers = cur.fetchall()
    finally:
        conn.close()

    return render_template(
        "staff_passengers.html",
        airline=airline,
        flight_num=flight_num,
        passengers=passengers
    )


# Customer history (only for matching airline to staff)
@app.route("/staff/customer_history", methods=["POST"])
@login_required("staff")
def staff_customer_history():
    airline_name = session["airline_name"]
    email = request.form.get("customer_email")

    conn = get_db_connection()
    history = []
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT f.*
                FROM purchases p
                JOIN ticket t ON p.ticket_id = t.ticket_id
                JOIN flight f ON f.airline_name = t.airline_name
                              AND f.flight_num = t.flight_num
                WHERE p.customer_email = %s
                  AND t.airline_name = %s
                ORDER BY f.departure_time DESC
            """, (email, airline_name))
            history = cur.fetchall()
    finally:
        conn.close()

    return render_template(
        "staff_customer_history.html",
        customer_email=email,
        flights=history
    )


# Staff analytics
@app.route("/staff/analytics")
@login_required("staff")
def staff_analytics():
    airline = session["airline_name"]
    conn = get_db_connection()
    data = {}

    try:
        with conn.cursor() as cur:
            # top agents last month by tickets
            cur.execute("""
                SELECT booking_agent_email, COUNT(*) AS tickets
                FROM purchases p
                JOIN ticket t USING(ticket_id)
                WHERE t.airline_name=%s
                  AND p.purchase_date >= DATE_SUB(CURDATE(), INTERVAL 1 MONTH)
                GROUP BY booking_agent_email
                ORDER BY tickets DESC
                LIMIT 5
            """, (airline,))
            data["top_agents_month"] = cur.fetchall()

            # top agents last year by commission
            cur.execute("""
                SELECT booking_agent_email,
                       SUM(purchase_price * 0.1) AS commission
                FROM purchases p
                JOIN ticket t USING(ticket_id)
                WHERE t.airline_name=%s
                  AND p.purchase_date >= DATE_SUB(CURDATE(), INTERVAL 1 YEAR)
                GROUP BY booking_agent_email
                ORDER BY commission DESC
                LIMIT 5
            """, (airline,))
            data["top_agents_year"] = cur.fetchall()

            # most frequent customer
            cur.execute("""
                SELECT p.customer_email, COUNT(*) AS flights
                FROM purchases p
                JOIN ticket t USING(ticket_id)
                WHERE t.airline_name=%s
                  AND p.purchase_date >= DATE_SUB(CURDATE(), INTERVAL 1 YEAR)
                GROUP BY p.customer_email
                ORDER BY flights DESC
                LIMIT 1
            """, (airline,))
            data["most_frequent"] = cur.fetchone()

            # tickets per month
            cur.execute("""
                SELECT DATE_FORMAT(p.purchase_date, '%%Y-%%m') AS month,
                       COUNT(*) AS tickets
                FROM purchases p
                JOIN ticket t USING(ticket_id)
                WHERE t.airline_name=%s
                  AND p.purchase_date >= DATE_SUB(CURDATE(), INTERVAL 1 YEAR)
                GROUP BY month
                ORDER BY month
            """, (airline,))
            data["tickets_per_month"] = cur.fetchall()

            # status counts
            cur.execute("""
                SELECT status, COUNT(*) AS count
                FROM flight
                WHERE airline_name=%s
                GROUP BY status
            """, (airline,))
            data["status_counts"] = cur.fetchall()

            # top destinations 3 months
            cur.execute("""
                SELECT f.arrival_airport, COUNT(*) AS trips
                FROM ticket t
                JOIN purchases p USING(ticket_id)
                JOIN flight f ON f.airline_name = t.airline_name
                             AND f.flight_num = t.flight_num
                WHERE t.airline_name=%s
                  AND p.purchase_date >= DATE_SUB(CURDATE(), INTERVAL 3 MONTH)
                GROUP BY f.arrival_airport
                ORDER BY trips DESC
                LIMIT 5
            """, (airline,))
            data["top_dest_3"] = cur.fetchall()

            # top destinations 1 year
            cur.execute("""
                SELECT f.arrival_airport, COUNT(*) AS trips
                FROM ticket t
                JOIN purchases p USING(ticket_id)
                JOIN flight f ON f.airline_name = t.airline_name
                             AND f.flight_num = t.flight_num
                WHERE t.airline_name=%s
                  AND p.purchase_date >= DATE_SUB(CURDATE(), INTERVAL 1 YEAR)
                GROUP BY f.arrival_airport
                ORDER BY trips DESC
                LIMIT 5
            """, (airline,))
            data["top_dest_year"] = cur.fetchall()
    finally:
        conn.close()

    return render_template("staff_analytics.html", data=data)


# Staff admin/operator actions

@app.route("/staff/create_flight", methods=["POST"])
@login_required("staff")
def staff_create_flight():
    role = session.get("staff_role")
    if role not in ("admin", "both"):
        flash("You do not have admin permission.")
        return redirect(url_for("staff_dashboard"))

    airline_name = session["airline_name"]
    flight_num = request.form.get("flight_num")
    departure_airport = request.form.get("departure_airport")
    arrival_airport = request.form.get("arrival_airport")
    departure_time = request.form.get("departure_time")
    arrival_time = request.form.get("arrival_time")
    base_price = request.form.get("base_price")
    airplane_id = request.form.get("airplane_id")

    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO flight
                (airline_name, flight_num, departure_airport, departure_time,
                 arrival_airport, arrival_time, base_price, status, airplane_id)
                VALUES (%s,%s,%s,%s,%s,%s,%s,'upcoming',%s)
            """, (
                airline_name, flight_num, departure_airport, departure_time,
                arrival_airport, arrival_time, base_price, airplane_id
            ))
        flash("Flight created.")
    finally:
        conn.close()

    return redirect(url_for("staff_dashboard"))


@app.route("/staff/update_status", methods=["POST"])
@login_required("staff")
def staff_update_status():
    role = session.get("staff_role")
    airline_name = session.get("airline_name")

    if role not in ("operator", "both"):
        flash("You do not have operator permission.", "error")
        return redirect(url_for("staff_dashboard"))

    flight_num = request.form.get("flight_num")
    status = request.form.get("status")

    if not flight_num or not status:
        flash("Please provide both a flight number and a new status.", "error")
        return redirect(url_for("staff_dashboard"))

    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE flight
                SET status = %s
                WHERE airline_name = %s
                  AND flight_num = %s
                """,
                (status, airline_name, flight_num),
            )

            if cur.rowcount == 0:
                flash("No flight with that number exists for your airline.", "error")
            else:
                flash("Flight status updated successfully.", "success")

    finally:
        conn.close()

    return redirect(url_for("staff_dashboard"))



@app.route("/staff/add_airplane", methods=["POST"])
@login_required("staff")
def staff_add_airplane():
    role = session.get("staff_role")
    if role not in ("admin", "both"):
        flash("You do not have admin permission.")
        return redirect(url_for("staff_dashboard"))

    airline_name = session["airline_name"]
    airplane_id = request.form.get("airplane_id")

    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO airplane (airline_name, airplane_id)
                VALUES (%s,%s)
            """, (airline_name, airplane_id))
        flash("Airplane added.")
    finally:
        conn.close()

    return redirect(url_for("staff_dashboard"))


@app.route("/staff/add_airport", methods=["POST"])
@login_required("staff")
def staff_add_airport():
    role = session.get("staff_role")
    if role not in ("admin", "both"):
        flash("You do not have admin permission.")
        return redirect(url_for("staff_dashboard"))

    name = request.form.get("airport_name")
    city = request.form.get("airport_city")

    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO airport (airport_name, airport_city)
                VALUES (%s,%s)
            """, (name, city))
        flash("Airport added.")
    finally:
        conn.close()

    return redirect(url_for("staff_dashboard"))


@app.route("/staff/add_agent_auth", methods=["POST"])
@login_required("staff")
def staff_add_agent_auth():
    role = session.get("staff_role")
    if role not in ("admin", "both"):
        flash("You do not have admin permission.")
        return redirect(url_for("staff_dashboard"))

    airline_name = session["airline_name"]
    agent_email = request.form.get("agent_email")

    conn = get_db_connection()
    try:
        with conn.cursor() as cur:

            # validate agent exists
            cur.execute("SELECT email FROM booking_agent WHERE email=%s", (agent_email,))
            if not cur.fetchone():
                flash("This booking agent does not exist.")
                return redirect(url_for("staff_dashboard"))

            # ensure airline still exists
            cur.execute("SELECT airline_name FROM airline WHERE airline_name=%s", (airline_name,))
            if not cur.fetchone():
                flash("Your airline is not valid.")
                return redirect(url_for("staff_dashboard"))

            # check if already authorized
            cur.execute("""
                SELECT *
                FROM agent_airline_authorization
                WHERE agent_email=%s AND airline_name=%s
            """, (agent_email, airline_name))

            if cur.fetchone():
                flash("This agent is already authorized for your airline.")
                return redirect(url_for("staff_dashboard"))

            # insert new authorization
            cur.execute("""
                INSERT INTO agent_airline_authorization (agent_email, airline_name)
                VALUES (%s,%s)
            """, (agent_email, airline_name))

            flash("Agent successfully authorized for this airline.")
    finally:
        conn.close()

    return redirect(url_for("staff_dashboard"))

# run everything
if __name__ == "__main__":
    app.run(debug=True)
