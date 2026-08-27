from flask import Flask, request, render_template_string, redirect
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///students.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)


class Student(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(30), nullable=False)


with app.app_context():
    db.create_all()


@app.route("/", methods=["GET", "POST"])
def register():

    message = ""

    if request.method == "POST":
        name = request.form["name"]
        email = request.form["email"]
        phone = request.form["phone"]

        student = Student(
            name=name,
            email=email,
            phone=phone
        )

        db.session.add(student)
        db.session.commit()

        message = "Registration successful!"

    return render_template_string("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Registration Form</title>

        <style>
            body {
                font-family: Arial;
                background: #f2f2f2;
            }

            .container {
                width: 400px;
                margin: 80px auto;
                background: white;
                padding: 30px;
                border-radius: 10px;
            }

            input {
                width: 100%;
                padding: 12px;
                margin: 10px 0;
                box-sizing: border-box;
            }

            button {
                width: 100%;
                padding: 12px;
                background: #2196f3;
                color: white;
                border: none;
                cursor: pointer;
            }

            a {
                display: block;
                margin-top: 20px;
                text-align: center;
            }
        </style>
    </head>

    <body>

    <div class="container">

        <h1>Registration</h1>

        <form method="POST">

            <input
                type="text"
                name="name"
                placeholder="Full Name"
                required
            >

            <input
                type="email"
                name="email"
                placeholder="Email"
                required
            >

            <input
                type="text"
                name="phone"
                placeholder="Phone Number"
                required
            >

            <button type="submit">
                Register
            </button>

        </form>

        <p>{{ message }}</p>

        <a href="/admin">
            Admin Dashboard
        </a>

    </div>

    </body>
    </html>
    """, message=message)


@app.route("/delete/<int:id>", methods=["POST"])
def delete_student(id):
    student = Student.query.get_or_404(id)
    db.session.delete(student)
    db.session.commit()
    return redirect("/admin")
@app.route("/admin")
def admin():

    students = Student.query.all()

    return render_template_string("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Admin Dashboard</title>

        <style>
            body {
                font-family: Arial;
                padding: 30px;
            }

            table {
                width: 100%;
                border-collapse: collapse;
            }

            th, td {
                border: 1px solid #ddd;
                padding: 12px;
                text-align: left;
            }

            th {
                background: #2196f3;
                color: white;
            }
        </style>
    </head>

    <body>

        <h1>Admin Dashboard</h1>

        <h3>Registered Students</h3>

        <table>

            <tr>
                <th>ID</th>
                <th>Name</th>
                <th>Email</th>
                <th>Phone</th>
            </tr>

           {% for student in students %}

    <tr>
        <td>{{ student.id }}</td>
        <td>{{ student.name }}</td>
        <td>{{ student.email }}</td>
        <td>{{ student.phone }}</td>

        <td>
            <form action="/delete/{{ student.id }}" method="POST">
                <button type="submit">Delete</button>
            </form>
        </td>
    </tr>

{% endfor %}

        </table>

        <br>

        <a href="/">Back to Registration</a>

    </body>
    </html>
    """, students=students)


if __name__ == "__main__":
    app.run(debug=True)