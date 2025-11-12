# Student Leave Management System

This is a simple backend server for a Student Leave Management System. It's written in Go and uses Chi for routing and GORM for the database.

It allows "student" users to log in and request leave, and "admin" users to log in and approve or reject those requests.

## 🚀 How to Run

1.  **Clone the project**
    ```bash
    git clone https://github.com/kalyan-vitwit/LeaveManagementSystem.git
    cd LeaveManagementSystem
    ```

2.  **Create your `.env` file**    
    *Create a file named `.env` and add the following:*
    ```env
    DATABASE_URL="host=localhost user=your_user password=your_password dbname=your_db port=5432 sslmode=disable"
    JWT_SECRET="your-super-secret-key-goes-here"
    ```

3.  **Install Dependencies**
    ```bash
    go mod tidy
    ```

4.  **Run the Server**
    ```bash
    go run .
    ```
    The server will start and be listening on `http://localhost:8080`.

## ⚙️ API Endpoints

Here is a simple list of all the API endpoints.

### Public Routes
These routes can be accessed by anyone.

* `GET /hello`
    * A simple test route to see if the server is running.

* `POST /login`
    * Lets any user (student or admin) log in. You send an email and password, and you get back a JWT token (a key).

### Student Routes
These routes require a JWT token to be sent in the `Authorization: Bearer <token>` header.

* `POST /leaves`
    * Lets the logged-in student create a new leave request.

* `GET /leaves`
    * Gets a list of all leave requests made by the logged-in student.

### Admin Routes
These routes require a JWT token from an **admin** user.

* `GET /admin/leaves/pending`
    * Gets a list of all leave requests from *all* students that are still "PENDING".

* `POST /admin/leaves/{id}/approve`
    * Approves a specific leave request. You put the leave ID in the URL (e.g., `/admin/leaves/123/approve`).

* `POST /admin/leaves/{id}/reject`
    * Rejects a specific leave request. You put the leave ID in the URL (e.g., `/admin/leaves/123/reject`).