function switchTab(tab) {
    const loginForm = document.getElementById("loginForm");
    const signupForm = document.getElementById("signupForm");
    const forgotForm = document.getElementById("forgotForm");
    const loginTab = document.getElementById("loginTab");
    const signupTab = document.getElementById("signupTab");
    const tabHeader = document.getElementById("tabHeader");

    loginForm.style.display = "none";
    signupForm.style.display = "none";
    forgotForm.style.display = "none";

    loginTab.classList.remove("active");
    signupTab.classList.remove("active");

    if (tab === "login") {
        loginForm.style.display = "block";
        loginTab.classList.add("active");
        if (tabHeader) tabHeader.style.display = "flex";
    } else if (tab === "signup") {
        signupForm.style.display = "block";
        signupTab.classList.add("active");
        if (tabHeader) tabHeader.style.display = "flex";
    } else if (tab === "forgot") {
        forgotForm.style.display = "block";
        if (tabHeader) tabHeader.style.display = "none";
    }
}

// LOGIN FUNCTION
async function login() {
    const roleSelect = document.getElementById("role").value;
    const studentId = document.getElementById("studentId").value.trim();
    const password = document.getElementById("password").value.trim();

    if (studentId === "" || password === "") {
        alert("Please enter User ID and Password");
        return;
    }

    try {
        let response;
        try {
            response = await fetch("http://localhost:3000/api/login", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ student_id: studentId, password: password })
            });
        } catch (err) {
            response = await fetch("http://127.0.0.1:3000/api/login", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ student_id: studentId, password: password })
            });
        }

        const data = await response.json();

        if (response.ok) {
            const userRole = String(data.user.role || "student").toLowerCase();
            const selectedRole = roleSelect.toLowerCase();

            if (selectedRole === "admin" && userRole !== "admin") {
                alert("Access Denied: This account does not have Administrator privileges.");
                return;
            }

            sessionStorage.setItem("lemsUser", JSON.stringify(data.user));
            sessionStorage.setItem("lemsToken", data.token);
            sessionStorage.setItem("lemsToken", data.token);

            if (userRole === "admin" || selectedRole === "admin") {
                window.location.href = "admin.html";
            } else {
                window.location.href = "dashboard.html";
            }
        } else {
            alert(data.message || "Login failed");
        }

    } catch (error) {
        alert("Cannot connect to LEMS server. Please ensure backend is running.");
        console.error("Login error:", error);
    }
}

// SIGNUP FUNCTION
async function signup() {
    const name = document.getElementById("signupName").value.trim();
    const studentId = document.getElementById("signupStudentId").value.trim();
    const email = document.getElementById("signupEmail").value.trim();
    const password = document.getElementById("signupPassword").value.trim();
    const role = "student";

    if (!name || !studentId || !email || !password) {
        alert("Please fill in all fields (Name, ID, Email, and Password).");
        return;
    }

    try {
        let response;
        try {
            response = await fetch("http://localhost:3000/api/signup", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    name: name,
                    student_id: studentId,
                    email: email,
                    password: password,
                    role: role
                })
            });
        } catch (err) {
            response = await fetch("http://127.0.0.1:3000/api/signup", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    name: name,
                    student_id: studentId,
                    email: email,
                    password: password,
                    role: role
                })
            });
        }

        const data = await response.json();

        if (response.ok) {
            alert(data.message || "Account created successfully! You can now log in.");

            document.getElementById("studentId").value = studentId;
            document.getElementById("role").value = role;
            switchTab("login");
        } else {
            alert(data.message || "Sign up failed.");
        }

    } catch (error) {
        console.error("Sign up error:", error);
        alert("Cannot connect to LEMS server. Please ensure backend is running.");
    }
}

// FORGOT PASSWORD FUNCTION
async function forgotPassword() {
    const emailInput = document.getElementById("forgotEmail");
    const messageEl = document.getElementById("forgotMessage");

    if (!emailInput) return;
    const email = emailInput.value.trim();

    if (!email) {
        messageEl.textContent = "❌ Please enter your registered email address.";
        messageEl.style.color = "red";
        return;
    }

    messageEl.textContent = "Requesting a password reset email...";
    messageEl.style.color = "#1976d2";

    try {
        let response;
        try {
            response = await fetch("http://localhost:3000/api/forgot-password", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ email: email })
            });
        } catch (err) {
            response = await fetch("http://127.0.0.1:3000/api/forgot-password", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ email: email })
            });
        }

        const data = await response.json();

        if (response.ok) {
            messageEl.textContent = "✅ " + (data.message || "If the account exists, a reset link will be sent to its registered email.");
            messageEl.style.color = "green";
        } else {
            messageEl.textContent = "❌ " + (data.message || "Unable to process the request.");
            messageEl.style.color = "red";
        }
    } catch (error) {
        console.error("Forgot password error:", error);
        messageEl.textContent = "❌ Cannot connect to server.";
        messageEl.style.color = "red";
    }
}
