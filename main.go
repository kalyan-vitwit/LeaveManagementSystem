package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt"
	"github.com/joho/godotenv"
	"github.com/kalyan-vitwit/LeaveManagementSystem/db"
)

// define a simple struct for JSON response
type Message struct {
	Message string `json:"message"`
}
type LoginPayload struct {
	Email string `json:"email"`
	Password string `json:"password"`
}
type LoginResponse struct {
	Token string `json:"token"`
}
type CreateLeavePayload struct {
	Reason string `json:"reason"`
	FromDate time.Time `json:"from_date"`
	ToDate time.Time `json:to_date`
}
type contextKey string
const userContextKey = contextKey("user")
const roleContextKey = contextKey("role")


func main() {
	godotenv.Load()

	url := os.Getenv("DATABASE_URL")
	if err := db.InitDB(url); err != nil {
		fmt.Printf("Error initializing DB: %v\n", err)
	}
	if err := db.SeedIfEmpty(); err != nil {
		fmt.Printf("Error Seeding DB: %v", err)
	}
	
	r := chi.NewRouter()

	// Define a GET endpoint /hello
	r.Get("/hello", func(w http.ResponseWriter, r *http.Request) {
		response := Message{Message: "Hello, World!"}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	})
	r.Post("/login", loginHandler)

	r.Group(func(r chi.Router) {
		r.Use(authMiddleware) // require JWT
		r.Post("/leaves", createLeaveHandler)
		r.Get("/leaves", listMyLeavesHandler)
	})

	// r.Group(func(r chi.Router) {
	// 	r.Use(authMiddleware)
	// 	r.Use(adminOnly)
	// 	r.Get("/admin/leaves/pending", listPendingHandler)
	// 	r.Post("/admin/leaves/{id}/approve", approveHandler)
	// 	r.Post("/admin/leaves/{id}/reject", rejectHandler)
	// })

	fmt.Println("Server on :8080")
	http.ListenAndServe(":8080", r)
}


func loginHandler(w http.ResponseWriter, r *http.Request) {
	var payload LoginPayload

	err := json.NewDecoder(r.Body).Decode(&payload)
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(Message{Message: "Invalid request payload"})
		return
	}

	user, err := db.GetUserByEmail(payload.Email)

	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(Message{Message: "User does not exist"})
		return
	}

	if !user.CheckPassword(payload.Password) {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(Message{Message: "Incorrect Password Sent"})
		return
	}

	// create'ing the claims
    claims := jwt.MapClaims{}

    claims["user_id"] = user.ID
    claims["user_role"] = user.Role

	// Sign the token with an algorithm and the claims
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
   
    tokenString, err := token.SignedString([]byte(os.Getenv("JWT_SECRET"))) 

    if err != nil {
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusInternalServerError)
        json.NewEncoder(w).Encode(Message{Message: "Token creation Error"})
        return
    }

    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusOK)
    json.NewEncoder(w).Encode(LoginResponse{Token: tokenString})
}

func createLeaveHandler(w http.ResponseWriter, r *http.Request) {
	var payload CreateLeavePayload

	err := json.NewDecoder(r.Body).Decode(&payload)
	w.Header().Set("Content-Type", "application/json")

	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(Message{Message: "Invalid request payload"})
	}

	userID := r.Context().Value(userContextKey).(uint)

	newLeave := db.Leave{
		UserID: userID,
		Reason: payload.Reason,
		FromDate: payload.FromDate,
		ToDate: payload.ToDate,
		Status: "PENDING",
	}

	result := db.DB.Create(&newLeave)

	if result.Error != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(Message{Message: "Could not create leave request"})
		return
	}
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(newLeave)
}

func authMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        authHeader := r.Header.Get("Authorization")

        if authHeader == "" {
            http.Error(w, "Authorization header required", http.StatusUnauthorized)
            return
        }

        tokenString := ""
        if len(authHeader) > 7 && authHeader[:7] == "Bearer " {
            tokenString = authHeader[7:]
        } else {
            http.Error(w, "Invalid authorization header format", http.StatusUnauthorized)
            return
        }

        claims := jwt.MapClaims{}
        token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
            return []byte(os.Getenv("JWT_SECRET")), nil
        })

        if err != nil || !token.Valid {
            http.Error(w, "Invalid token", http.StatusUnauthorized)
            return
        }

        userIDFloat, ok := claims["user_id"].(float64)
        if !ok {
            http.Error(w, "Invalid token: user_id missing or invalid", http.StatusUnauthorized)
            return
        }
        userID := int(userIDFloat) 

        userRole, ok := claims["user_role"].(string)
        if !ok {
            http.Error(w, "Invalid token: user_role missing or invalid", http.StatusUnauthorized)
            return
        }

        ctx := r.Context()
        ctx = context.WithValue(ctx, userContextKey, userID)
        ctx = context.WithValue(ctx, roleContextKey, userRole)

        next.ServeHTTP(w, r.WithContext(ctx))
    })
}

func listMyLeavesHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value(userContextKey).(uint)

	var myLeaves []db.Leave

	result := db.DB.Where("user_id = ?", userID).Find(&myLeaves)

	if result.Error != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(Message{Message: "Was not able to find the leaves"})
		return
	}

	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(myLeaves)
}