from flask import (
    Blueprint,
    render_template,
    redirect,
    session,
    url_for,
    request,
    jsonify,
    Response,
)
from pymongo import MongoClient
from bson import ObjectId
import bcrypt

main = Blueprint("main", __name__)

# MongoDB configuration
client = MongoClient("mongodb://localhost:27017/")
db = client["taskedb"]
users_collection = db["users"]
tasks_collection = db["tasks"]


@main.route("/")
def index():
    return render_template("index.html")


@main.route("/register", methods=["POST"])
def register():
    name = request.form.get("name")
    username = request.form.get("username")
    email = request.form.get("email")
    password = request.form.get("password")

    # Hash the password
    hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

    # Check if the user already exists (by username or email)
    if users_collection.find_one({"$or": [{"username": username}, {"email": email}]}):
        return redirect(url_for("main.index"))

    # Insert the new user into the collection
    new_user = {
        "name": name,
        "username": username,
        "email": email,
        "password": hashed_password,
    }
    # Change this line to insert into the "users" collection
    users_collection.insert_one(new_user)

    return redirect(url_for("main.login"))


@main.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        # Handle the login form submission
        username_or_email = request.form.get("username_or_email")
        password = request.form.get("password")

        user = users_collection.find_one(
            {"$or": [{"username": username_or_email}, {"email": username_or_email}]}
        )

        if user and bcrypt.checkpw(password.encode("utf-8"), user["password"]):
            # Successful login
            # Redirect to the tasks page after successful login
            session["user_id"] = user["username"]  # Store username in session
            return redirect(url_for("main.tasks"))

    # If the request method is GET or login failed, or if there was no POST data, render the login form.
    return render_template("login.html")


@main.route("/tasks")
def tasks():
    user_username = session.get("user_id")
    if user_username is None:
        return redirect(url_for("main.login"))

    user = users_collection.find_one({"username": user_username})

    if user is None:
        return redirect(url_for("main.login"))

    # Retrieve the user's tasks
    user_tasks = list(tasks_collection.find({"user_id": user_username}))

    return render_template("tasks.html", tasked=user_tasks, current_user=user)


@main.route("/add_task", methods=["POST"])
def add_task():
    try:
        if "user_id" not in session:
            return redirect(url_for("main.login"))

        user_username = session["user_id"]
        user = users_collection.find_one({"username": user_username})

        if user is None:
            return redirect(url_for("main.login"))

        new_task_text = request.form.get("new-task")
        print(f"New task text: {new_task_text}")

        if new_task_text:
            new_task = {
                "user_id": user_username,
                "text": new_task_text,
                "complete": False,
            }
            result = tasks_collection.insert_one(new_task)
            if result.inserted_id:
                print("Task inserted successfully")
            else:
                print("Task insertion failed")
        else:
            print("No new task text provided")

        return redirect(url_for("main.tasks"))
    except Exception as e:
        print(f"An error occurred: {str(e)}")
        return redirect(url_for("main.tasks"))


@main.route("/complete_task/<task_id>", methods=["POST"])
def complete_task(task_id):
    if "user_id" not in session:
        return redirect(url_for("main.login"))

    user_username = session["user_id"]
    user = users_collection.find_one({"username": user_username})

    if user is None:
        return redirect(url_for("main.login"))

    # Assuming you have a tasks_collection
    task = tasks_collection.find_one({"_id": ObjectId(task_id)})

    if task is None:
        return redirect(url_for("main.tasks"))

    # Update the task to mark it as completed
    tasks_collection.update_one(
        {"_id": ObjectId(task_id)}, {"$set": {"complete": True}}
    )

    return redirect(url_for("main.tasks"))


@main.route("/delete_completed", methods=["POST"])
def delete_completed():
    try:
        if "user_id" not in session:
            return redirect(url_for("main.login"))

        user_username = session["user_id"]
        user = users_collection.find_one({"username": user_username})

        if user is None:
            return redirect(url_for("main.login"))

        # Delete all completed tasks for the current user
        result = tasks_collection.delete_many(
            {"user_id": user_username, "complete": True}
        )

        return redirect(url_for("main.tasks"))
    except Exception as e:
        return redirect(url_for("main.tasks"))


@main.route("/delete_task/<task_id>", methods=["POST"])
def delete_task(task_id):
    if "user_id" not in session:
        return redirect(url_for("main.login"))

    user_username = session["user_id"]
    user = users_collection.find_one({"username": user_username})

    if user is None:
        return redirect(url_for("main.login"))

    # Use ObjectId to match the task ID
    from bson import ObjectId

    task_id_obj = ObjectId(task_id)
    tasks_collection.delete_one({"_id": task_id_obj, "user_id": user_username})
    return redirect(url_for("main.tasks"))


@main.route("/delete_all", methods=["POST"])
def delete_all():
    if "user_id" not in session:
        return redirect(url_for("main.login"))

    user_username = session["user_id"]
    user = users_collection.find_one({"username": user_username})

    if user is None:
        return redirect(url_for("main.login"))

    tasks_collection.delete_many({"user_id": user_username})
    return redirect(url_for("main.tasks"))


@main.route("/logout")
def logout():
    session.clear()  # Clear the user's session data
    return redirect(url_for("main.index"))
