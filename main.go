package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"html/template"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/labstack/echo/v5"
	"golang.org/x/crypto/bcrypt"
)

type Post struct {
	ID        int
	Title     string
	Content   string
	Author    string
	Image     string
	IsPrivate bool
}

type Comment struct {
	ID        int
	Content   string
	Author    string
	CreatedAt time.Time
}

type ShareUser struct {
	ID       int
	Username string
}

type RegisterRequest struct {
	Username string `form:"username"`
	Password string `form:"password"`
}

type LoginRequest struct {
	Username string `form:"username"`
	Password string `form:"password"`
}

type ChangePasswordRequest struct {
	CurrentPassword string `form:"current_password"`
	NewPassword     string `form:"new_password"`
	ConfirmPassword string `form:"confirm_password"`
}

type ChangeUsernameRequest struct {
	Username string `form:"username"`
}

type CreatePostRequest struct {
	Title     string `form:"title"`
	Content   string `form:"content"`
	IsPrivate string `form:"is_private"`
	ShareWith string `form:"share_with"`
}

type CreateCommentRequest struct {
	Content string `form:"content"`
}

type SharePostRequest struct {
	Username string `form:"username"`
}

type ProfileData struct {
	ID       int
	Username string
}

type Session struct {
	UserID int
	Expire time.Time
}

type SessionManager struct {
	mu       sync.RWMutex
	sessions map[string]Session
}

var sessionManager = SessionManager{
	sessions: make(map[string]Session),
}

func (sm *SessionManager) Set(sessionID string, userID int, duration time.Duration) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.sessions[sessionID] = Session{UserID: userID, Expire: time.Now().Add(duration)}
}

func (sm *SessionManager) Get(sessionID string) (int, bool) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	session, exists := sm.sessions[sessionID]
	if !exists {
		return 0, false
	}
	if time.Now().After(session.Expire) {
		delete(sm.sessions, sessionID)
		return 0, false
	}
	return session.UserID, true
}

func (sm *SessionManager) Delete(sessionID string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	delete(sm.sessions, sessionID)
}

func (sm *SessionManager) StartCleanup(interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for range ticker.C {
			sm.mu.Lock()
			now := time.Now()
			for id, s := range sm.sessions {
				if now.After(s.Expire) {
					delete(sm.sessions, id)
				}
			}
			sm.mu.Unlock()
		}
	}()
}

type RateLimiter struct {
	mu       sync.Mutex
	requests map[string][]time.Time
}

func (rl *RateLimiter) Allow(key string, limit int, window time.Duration) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-window)

	var recent []time.Time
	for _, t := range rl.requests[key] {
		if t.After(cutoff) {
			recent = append(recent, t)
		}
	}

	if len(recent) >= limit {
		rl.requests[key] = recent
		return false
	}

	rl.requests[key] = append(recent, now)
	return true
}

func (rl *RateLimiter) StartCleanup(interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for range ticker.C {
			rl.mu.Lock()
			cutoff := time.Now().Add(-interval)
			for key, times := range rl.requests {
				stillRecent := false
				for _, t := range times {
					if t.After(cutoff) {
						stillRecent = true
						break
					}
				}
				if !stillRecent {
					delete(rl.requests, key)
				}
			}
			rl.mu.Unlock()
		}
	}()
}

var loginLimiter = RateLimiter{requests: make(map[string][]time.Time)}
var registerLimiter = RateLimiter{requests: make(map[string][]time.Time)}

func rateLimit(rl *RateLimiter, limit int, window time.Duration) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			ip := c.RealIP()
			if !rl.Allow(ip, limit, window) {
				return c.String(http.StatusTooManyRequests, "too many requests, please try again later")
			}
			return next(c)
		}
	}
}

func securityHeaders(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c *echo.Context) error {
		h := c.Response().Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		return next(c)
	}
}

func csrfProtection(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c *echo.Context) error {
		method := c.Request().Method
		if method != http.MethodPost && method != http.MethodPut &&
			method != http.MethodPatch && method != http.MethodDelete {
			return next(c)
		}

		source := c.Request().Header.Get("Origin")
		if source == "" {
			source = c.Request().Header.Get("Referer")
		}
		if source == "" {

			return next(c)
		}

		u, err := url.Parse(source)
		if err != nil || !strings.EqualFold(u.Host, c.Request().Host) {
			return c.String(http.StatusForbidden, "invalid request origin")
		}

		return next(c)
	}
}

var db *pgx.Conn

var isProduction = strings.ToLower(os.Getenv("APP_ENV")) == "production"

func main() {
	var err error

	db, err = connectDB()
	if err != nil {
		panic(err)
	}

	e := echo.New()

	e.Use(securityHeaders)
	e.Use(csrfProtection)

	renderer := &TemplateRenderer{
		templates: template.Must(template.ParseGlob("templates/*.html")),
	}
	e.Renderer = renderer

	e.Static("/uploads", "uploads")

	e.GET("/", home)

	// Authentication
	e.GET("/register", registerPage)
	e.POST("/register", register, rateLimit(&registerLimiter, 5, time.Minute))
	e.GET("/login", loginPage)
	e.POST("/login", login, rateLimit(&loginLimiter, 5, time.Minute))
	e.GET("/logout", logout)

	e.GET("/blog", blog, auth)
	e.GET("/blog/posts/:id", postsPage, auth)
	e.GET("/dashboard", dashboard, auth)
	e.GET("/posts/new", createPostPage, auth)
	e.POST("/posts", createPost, auth)
	e.GET("/posts/:id", getPost, auth)
	e.DELETE("/posts/:id", deletePost, auth)
	e.GET("/api/posts", posts, auth)

	e.GET("/posts/:id/comments", getComments, auth)
	e.POST("/posts/:id/comments", createComment, auth)

	e.POST("/posts/:id/share", sharePost, auth)
	e.GET("/posts/:id/shares", getShares, auth)
	e.DELETE("/posts/:id/shares/:user_id", removeShare, auth)
	e.GET("/posts/:id/shares/manage", shareManagementPage, auth)

	e.GET("/profile", profile, auth)
	e.GET("/change-password", changePasswordPage, auth)
	e.POST("/change-password", changePassword, auth)
	e.GET("/change-username", changeUsernamePage, auth)
	e.POST("/change-username", changeUsername, auth)

	sessionManager.StartCleanup(10 * time.Minute)
	loginLimiter.StartCleanup(10 * time.Minute)
	registerLimiter.StartCleanup(10 * time.Minute)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8000"
	}

	srv := &http.Server{
		Addr:              ":" + port,
		Handler:           e,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		MaxHeaderBytes:    1 << 20, // 1MB
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatal("server error: ", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	<-quit

	log.Println("shutting down...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Println("shutdown error:", err)
	}

	db.Close(context.Background())
}

// auth is route middleware that requires a valid session cookie and
// injects the authenticated user_id into the request context.
func auth(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c *echo.Context) error {
		cookie, err := c.Cookie("session_id")
		if err != nil {
			return c.String(http.StatusUnauthorized, "Not logged in")
		}

		userID, exists := sessionManager.Get(cookie.Value)
		if !exists {
			return c.String(http.StatusUnauthorized, "Not logged in")
		}

		c.Set("user_id", userID)
		return next(c)
	}
}

func home(c *echo.Context) error {
	cookie, err := c.Cookie("session_id")
	if err == nil {
		if _, exists := sessionManager.Get(cookie.Value); exists {
			return c.Redirect(http.StatusSeeOther, "/blog")
		}
	}

	return c.Render(http.StatusOK, "home", nil)
}

func registerPage(c *echo.Context) error {
	return c.Render(http.StatusOK, "register", nil)
}

func register(c *echo.Context) error {
	var req RegisterRequest

	if err := c.Bind(&req); err != nil {
		return err
	}

	req.Username = strings.TrimSpace(req.Username)

	if req.Username == "" || req.Password == "" {
		return c.String(http.StatusBadRequest, "username or password is empty")
	}

	if !isValidUsername(req.Username) {
		return c.String(http.StatusBadRequest, "username must be 3-20 characters: letters, numbers, underscore")
	}

	if len(req.Password) < 8 {
		return c.String(http.StatusBadRequest, "password must be at least 8 characters")
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return internalError(c, err)
	}

	_, err = db.Exec(
		c.Request().Context(),
		`INSERT INTO users (username, password) VALUES ($1, $2)`,
		req.Username,
		hashedPassword,
	)
	if err != nil {
		return c.String(http.StatusConflict, "username already exists")
	}

	return c.Redirect(http.StatusFound, "/login")
}

func loginPage(c *echo.Context) error {
	return c.Render(http.StatusOK, "login", nil)
}

func login(c *echo.Context) error {
	var req LoginRequest

	if err := c.Bind(&req); err != nil {
		return err
	}

	req.Username = strings.TrimSpace(req.Username)

	if req.Username == "" || req.Password == "" {
		return c.String(http.StatusBadRequest, "username or password is empty")
	}

	var id int
	var username string
	var hashedPassword string

	row := db.QueryRow(
		c.Request().Context(),
		`SELECT id, username, password FROM users WHERE username = $1`,
		req.Username,
	)

	err := row.Scan(&id, &username, &hashedPassword)
	if errors.Is(err, pgx.ErrNoRows) {
		return c.String(http.StatusUnauthorized, "invalid username or password")
	}
	if err != nil {
		return internalError(c, err)
	}

	if err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(req.Password)); err != nil {
		return c.String(http.StatusUnauthorized, "invalid username or password")
	}

	sessionID, err := generateSessionID()
	if err != nil {
		return internalError(c, err)
	}

	sessionManager.Set(sessionID, id, 24*time.Hour)

	c.SetCookie(&http.Cookie{
		Name:     "session_id",
		Value:    sessionID,
		HttpOnly: true,
		Secure:   isProduction,
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
		MaxAge:   24 * 60 * 60,
	})

	return c.Redirect(http.StatusSeeOther, "/dashboard")
}

func logout(c *echo.Context) error {
	cookie, err := c.Cookie("session_id")
	if err == nil {
		sessionManager.Delete(cookie.Value)
	}

	c.SetCookie(&http.Cookie{
		Name:     "session_id",
		Value:    "",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   isProduction,
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
	})

	return c.Redirect(http.StatusSeeOther, "/")
}

func profile(c *echo.Context) error {
	userID := c.Get("user_id").(int)

	var user ProfileData

	row := db.QueryRow(
		c.Request().Context(),
		`SELECT id, username FROM users WHERE id = $1`,
		userID,
	)

	err := row.Scan(&user.ID, &user.Username)
	if errors.Is(err, pgx.ErrNoRows) {
		return c.String(http.StatusNotFound, "user not found")
	}
	if err != nil {
		return internalError(c, err)
	}

	return c.Render(http.StatusOK, "profile", user)
}

func changeUsernamePage(c *echo.Context) error {
	return c.Render(http.StatusOK, "change-username", nil)
}

func changeUsername(c *echo.Context) error {
	userID := c.Get("user_id").(int)

	var req ChangeUsernameRequest
	if err := c.Bind(&req); err != nil {
		return err
	}

	req.Username = strings.TrimSpace(req.Username)

	if !isValidUsername(req.Username) {
		return c.String(http.StatusBadRequest, "username must be 3-20 characters: letters, numbers, underscore")
	}

	var exists bool

	err := db.QueryRow(
		c.Request().Context(),
		`SELECT EXISTS(SELECT 1 FROM users WHERE username = $1 AND id != $2)`,
		req.Username,
		userID,
	).Scan(&exists)
	if err != nil {
		return internalError(c, err)
	}
	if exists {
		return c.String(http.StatusConflict, "username already exists")
	}

	_, err = db.Exec(
		c.Request().Context(),
		`UPDATE users SET username = $1 WHERE id = $2`,
		req.Username,
		userID,
	)
	if err != nil {
		return internalError(c, err)
	}

	return c.Redirect(http.StatusFound, "/profile")
}

func changePasswordPage(c *echo.Context) error {
	return c.Render(http.StatusOK, "change-password", nil)
}

func changePassword(c *echo.Context) error {
	userID := c.Get("user_id").(int)

	var req ChangePasswordRequest
	if err := c.Bind(&req); err != nil {
		return err
	}

	if req.ConfirmPassword == "" || req.NewPassword == "" || req.CurrentPassword == "" {
		return c.String(http.StatusBadRequest, "All fields are required.")
	}
	if len(req.NewPassword) < 8 {
		return c.String(http.StatusBadRequest, "Password must be at least 8 characters.")
	}
	if req.NewPassword != req.ConfirmPassword {
		return c.String(http.StatusBadRequest, "New passwords do not match.")
	}

	var hashedPassword string

	row := db.QueryRow(
		c.Request().Context(),
		`SELECT password FROM users WHERE id = $1`,
		userID,
	)

	err := row.Scan(&hashedPassword)
	if errors.Is(err, pgx.ErrNoRows) {
		return c.String(http.StatusNotFound, "User not found.")
	}
	if err != nil {
		return internalError(c, err)
	}

	if err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(req.CurrentPassword)); err != nil {
		return c.String(http.StatusUnauthorized, "Current password is incorrect.")
	}

	newHashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		return internalError(c, err)
	}

	_, err = db.Exec(
		c.Request().Context(),
		`UPDATE users SET password = $1 WHERE id = $2`,
		newHashedPassword,
		userID,
	)
	if err != nil {
		return internalError(c, err)
	}

	return c.String(http.StatusOK, "Password changed successfully.")
}

func dashboard(c *echo.Context) error {
	userID := c.Get("user_id").(int)

	rows, err := db.Query(
		c.Request().Context(),
		`
        SELECT id, title, content, COALESCE(image, ''), is_private
        FROM posts
        WHERE author_id = $1
        ORDER BY id DESC
        `,
		userID,
	)
	if err != nil {
		return internalError(c, err)
	}
	defer rows.Close()

	var posts []Post

	for rows.Next() {
		var post Post
		if err := rows.Scan(&post.ID, &post.Title, &post.Content, &post.Image, &post.IsPrivate); err != nil {
			return internalError(c, err)
		}
		post.Image = filepath.ToSlash(post.Image)
		posts = append(posts, post)
	}
	if err := rows.Err(); err != nil {
		return internalError(c, err)
	}

	return c.Render(http.StatusOK, "dashboard", posts)
}

func blog(c *echo.Context) error {
	userID := c.Get("user_id").(int)

	rows, err := db.Query(
		c.Request().Context(),
		`
        SELECT posts.id, posts.title, posts.content, users.username, COALESCE(posts.image, ''), posts.is_private
        FROM posts
        JOIN users ON posts.author_id = users.id
        WHERE
            posts.is_private = false
            OR posts.author_id = $1
            OR EXISTS (
                SELECT 1 FROM post_shares
                WHERE post_shares.post_id = posts.id AND post_shares.user_id = $1
            )
        ORDER BY posts.id DESC
        `,
		userID,
	)
	if err != nil {
		return internalError(c, err)
	}
	defer rows.Close()

	var posts []Post

	for rows.Next() {
		var post Post
		if err := rows.Scan(&post.ID, &post.Title, &post.Content, &post.Author, &post.Image, &post.IsPrivate); err != nil {
			return internalError(c, err)
		}
		post.Image = filepath.ToSlash(post.Image)
		posts = append(posts, post)
	}
	if err := rows.Err(); err != nil {
		return internalError(c, err)
	}

	return c.Render(http.StatusOK, "blog", posts)
}

func posts(c *echo.Context) error {
	userID := c.Get("user_id").(int)

	rows, err := db.Query(
		c.Request().Context(),
		`
    SELECT posts.id, posts.title, posts.content, users.username, COALESCE(posts.image, ''), posts.is_private
    FROM posts
    JOIN users ON posts.author_id = users.id
    WHERE
        posts.is_private = false
        OR posts.author_id = $1
        OR EXISTS (
            SELECT 1 FROM post_shares
            WHERE post_shares.post_id = posts.id AND post_shares.user_id = $1
        )
    ORDER BY posts.id DESC
    `,
		userID,
	)
	if err != nil {
		return internalError(c, err)
	}
	defer rows.Close()

	var posts []Post

	for rows.Next() {
		var post Post
		if err := rows.Scan(&post.ID, &post.Title, &post.Content, &post.Author, &post.Image, &post.IsPrivate); err != nil {
			return internalError(c, err)
		}
		post.Image = filepath.ToSlash(post.Image)
		posts = append(posts, post)
	}
	if err := rows.Err(); err != nil {
		return internalError(c, err)
	}

	return c.JSON(http.StatusOK, posts)
}

func postsPage(c *echo.Context) error {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		return c.String(http.StatusBadRequest, "Invalid Post ID")
	}

	userID := c.Get("user_id").(int)

	var post Post

	row := db.QueryRow(
		c.Request().Context(),
		`
        SELECT posts.id, posts.title, posts.content, users.username, COALESCE(posts.image, ''), posts.is_private
        FROM posts
        JOIN users ON posts.author_id = users.id
        WHERE posts.id = $1
        AND (
            posts.is_private = false
            OR posts.author_id = $2
            OR EXISTS (
                SELECT 1 FROM post_shares
                WHERE post_shares.post_id = posts.id AND post_shares.user_id = $2
            )
        )
        `,
		id,
		userID,
	)

	err = row.Scan(&post.ID, &post.Title, &post.Content, &post.Author, &post.Image, &post.IsPrivate)
	if errors.Is(err, pgx.ErrNoRows) {
		return c.String(http.StatusNotFound, "Post not found")
	}
	if err != nil {
		return internalError(c, err)
	}

	post.Image = filepath.ToSlash(post.Image)

	return c.Render(http.StatusOK, "post", post)
}

func createPostPage(c *echo.Context) error {
	return c.Render(http.StatusOK, "create", nil)
}

func createPost(c *echo.Context) error {
	var req CreatePostRequest
	if err := c.Bind(&req); err != nil {
		return err
	}

	req.Title = strings.TrimSpace(req.Title)
	req.Content = strings.TrimSpace(req.Content)

	if req.Title == "" || req.Content == "" {
		return c.String(http.StatusBadRequest, "title or content is empty")
	}

	isPrivate := req.IsPrivate == "on"
	userID := c.Get("user_id").(int)
	ctx := c.Request().Context()

	var filePath string

	file, err := c.FormFile("image")
	if err == nil && file != nil {
		filePath, err = savePostImage(file)
		if err != nil {
			return c.String(http.StatusBadRequest, err.Error())
		}
	}

	committed := false
	defer func() {
		if !committed && filePath != "" {
			os.Remove(filePath)
		}
	}()

	tx, err := db.Begin(ctx)
	if err != nil {
		return internalError(c, err)
	}
	defer tx.Rollback(ctx) // no-op once Commit succeeds

	var postID int

	err = tx.QueryRow(
		ctx,
		`
    INSERT INTO posts (title, content, author_id, image, is_private)
    VALUES ($1, $2, $3, $4, $5)
    RETURNING id
    `,
		req.Title,
		req.Content,
		userID,
		filePath,
		isPrivate,
	).Scan(&postID)
	if err != nil {
		return internalError(c, err)
	}

	if isPrivate && strings.TrimSpace(req.ShareWith) != "" {
		if err := shareWithUsernames(ctx, tx, postID, userID, req.ShareWith); err != nil {
			return c.String(http.StatusBadRequest, err.Error())
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return internalError(c, err)
	}
	committed = true

	return c.Redirect(http.StatusSeeOther, "/dashboard")
}

func getPost(c *echo.Context) error {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		return c.String(http.StatusBadRequest, "Invalid post ID")
	}

	userID := c.Get("user_id").(int)

	row := db.QueryRow(
		c.Request().Context(),
		`
    SELECT posts.id, posts.title, posts.content, users.username, COALESCE(posts.image, ''), posts.is_private
    FROM posts
    JOIN users ON posts.author_id = users.id
    WHERE posts.id = $1
    AND (
        posts.is_private = false
        OR posts.author_id = $2
        OR EXISTS (
            SELECT 1 FROM post_shares
            WHERE post_shares.post_id = posts.id AND post_shares.user_id = $2
        )
    )
    `,
		id,
		userID,
	)

	var post Post

	err = row.Scan(&post.ID, &post.Title, &post.Content, &post.Author, &post.Image, &post.IsPrivate)
	if errors.Is(err, pgx.ErrNoRows) {
		return c.String(http.StatusNotFound, "Post not found")
	}
	if err != nil {
		return internalError(c, err)
	}

	post.Image = filepath.ToSlash(post.Image)

	return c.JSON(http.StatusOK, post)
}

func deletePost(c *echo.Context) error {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		return c.String(http.StatusBadRequest, "Invalid post ID")
	}

	userID := c.Get("user_id").(int)

	result, err := db.Exec(
		c.Request().Context(),
		`DELETE FROM posts WHERE id = $1 AND author_id = $2`,
		id,
		userID,
	)
	if err != nil {
		return internalError(c, err)
	}
	if result.RowsAffected() == 0 {
		return c.String(http.StatusNotFound, "Post not found")
	}

	return c.String(http.StatusOK, "Post deleted successfully")
}

func getComments(c *echo.Context) error {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		return c.String(http.StatusBadRequest, "Invalid post id")
	}

	userID := c.Get("user_id").(int)
	ctx := c.Request().Context()

	visible, err := postIsVisibleTo(ctx, id, userID)
	if err != nil {
		return internalError(c, err)
	}
	if !visible {
		return c.String(http.StatusNotFound, "post not found")
	}

	rows, err := db.Query(
		ctx,
		`
		SELECT comments.id, comments.content, users.username, comments.created_at
		FROM comments
		JOIN users ON comments.user_id = users.id
		WHERE comments.post_id = $1
		ORDER BY comments.created_at ASC
		`,
		id,
	)
	if err != nil {
		return internalError(c, err)
	}
	defer rows.Close()

	var comments []Comment

	for rows.Next() {
		var comment Comment
		if err := rows.Scan(&comment.ID, &comment.Content, &comment.Author, &comment.CreatedAt); err != nil {
			return internalError(c, err)
		}
		comments = append(comments, comment)
	}
	if err := rows.Err(); err != nil {
		return internalError(c, err)
	}

	return c.JSON(http.StatusOK, comments)
}

func createComment(c *echo.Context) error {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		return c.String(http.StatusBadRequest, "Invalid post id")
	}

	userID := c.Get("user_id").(int)
	ctx := c.Request().Context()

	var req CreateCommentRequest
	if err := c.Bind(&req); err != nil {
		return c.String(http.StatusBadRequest, "Invalid request")
	}

	req.Content = strings.TrimSpace(req.Content)
	if req.Content == "" {
		return c.String(http.StatusBadRequest, "Comment cannot be empty")
	}

	visible, err := postIsVisibleTo(ctx, id, userID)
	if err != nil {
		return internalError(c, err)
	}
	if !visible {
		return c.String(http.StatusNotFound, "post not found")
	}

	_, err = db.Exec(
		ctx,
		`INSERT INTO comments (post_id, user_id, content) VALUES ($1, $2, $3)`,
		id,
		userID,
		req.Content,
	)
	if err != nil {
		return internalError(c, err)
	}

	return c.JSON(http.StatusCreated, map[string]string{
		"message": "Comment created successfully",
	})
}

func shareManagementPage(c *echo.Context) error {
	return c.Render(http.StatusOK, "shares", nil)
}

func sharePost(c *echo.Context) error {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		return c.String(http.StatusBadRequest, "invalid post id")
	}

	userID := c.Get("user_id").(int)
	ctx := c.Request().Context()

	var req SharePostRequest
	if err := c.Bind(&req); err != nil {
		return c.String(http.StatusBadRequest, "invalid request")
	}

	req.Username = strings.TrimSpace(req.Username)
	if req.Username == "" {
		return c.String(http.StatusBadRequest, "Username is required")
	}

	var isPrivate bool

	err = db.QueryRow(
		ctx,
		`SELECT is_private FROM posts WHERE id = $1 AND author_id = $2`,
		id,
		userID,
	).Scan(&isPrivate)
	if errors.Is(err, pgx.ErrNoRows) {
		return c.String(http.StatusNotFound, "post not found")
	}
	if err != nil {
		return internalError(c, err)
	}
	if !isPrivate {
		return c.String(http.StatusUnauthorized, "Only private posts can be shared")
	}

	var sharedUserID int

	err = db.QueryRow(
		ctx,
		`SELECT id FROM users WHERE username = $1`,
		req.Username,
	).Scan(&sharedUserID)
	if errors.Is(err, pgx.ErrNoRows) {
		return c.String(http.StatusNotFound, "user not found")
	}
	if err != nil {
		return internalError(c, err)
	}
	if sharedUserID == userID {
		return c.String(http.StatusForbidden, "You cannot share a post with yourself")
	}

	_, err = db.Exec(
		ctx,
		`INSERT INTO post_shares (post_id, user_id) VALUES ($1, $2) ON CONFLICT (post_id, user_id) DO NOTHING`,
		id,
		sharedUserID,
	)
	if err != nil {
		return internalError(c, err)
	}

	return c.JSON(http.StatusOK, map[string]string{
		"message": "Post shared successfully",
	})
}

func getShares(c *echo.Context) error {
	postID, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		return c.String(http.StatusBadRequest, "Invalid Post ID")
	}

	userID := c.Get("user_id").(int)
	ctx := c.Request().Context()

	var owns bool

	err = db.QueryRow(
		ctx,
		`SELECT EXISTS(SELECT 1 FROM posts WHERE id = $1 AND author_id = $2)`,
		postID,
		userID,
	).Scan(&owns)
	if err != nil {
		return internalError(c, err)
	}
	if !owns {
		return c.String(http.StatusNotFound, "You are not the owner")
	}

	rows, err := db.Query(
		ctx,
		`
		SELECT users.id, users.username
		FROM post_shares
		JOIN users ON users.id = post_shares.user_id
		WHERE post_shares.post_id = $1
		ORDER BY users.username
		`,
		postID,
	)
	if err != nil {
		return internalError(c, err)
	}
	defer rows.Close()

	var users []ShareUser

	for rows.Next() {
		var user ShareUser
		if err := rows.Scan(&user.ID, &user.Username); err != nil {
			return internalError(c, err)
		}
		users = append(users, user)
	}

	return c.JSON(http.StatusOK, users)
}

func removeShare(c *echo.Context) error {
	postID, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		return c.String(http.StatusBadRequest, "Invalid post ID")
	}

	sharedUserID, err := strconv.Atoi(c.Param("user_id"))
	if err != nil {
		return c.String(http.StatusBadRequest, "Invalid user ID")
	}

	ownerID := c.Get("user_id").(int)
	ctx := c.Request().Context()

	var owns bool

	err = db.QueryRow(
		ctx,
		`SELECT EXISTS(SELECT 1 FROM posts WHERE id = $1 AND author_id = $2)`,
		postID,
		ownerID,
	).Scan(&owns)
	if err != nil {
		return internalError(c, err)
	}
	if !owns {
		return c.String(http.StatusForbidden, "You are not the owner")
	}

	result, err := db.Exec(
		ctx,
		`DELETE FROM post_shares WHERE post_id = $1 AND user_id = $2`,
		postID,
		sharedUserID,
	)
	if err != nil {
		return internalError(c, err)
	}
	if result.RowsAffected() == 0 {
		return c.String(http.StatusNotFound, "Share not found")
	}

	return c.JSON(http.StatusOK, map[string]string{
		"message": "Share removed successfully",
	})
}

func internalError(c *echo.Context, err error) error {
	log.Println("internal error:", err)
	return c.String(http.StatusInternalServerError, "something went wrong, please try again later")
}

var usernameRegex = regexp.MustCompile(`^[a-zA-Z0-9_]{3,20}$`)

func isValidUsername(username string) bool {
	return usernameRegex.MatchString(username)
}

func generateSessionID() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func generateFileName(originalName string) (string, error) {
	ext := strings.ToLower(filepath.Ext(originalName))

	allowedExtensions := map[string]bool{
		".jpg":  true,
		".jpeg": true,
		".png":  true,
		".gif":  true,
		".webp": true,
	}
	if !allowedExtensions[ext] {
		return "", errors.New("invalid image extension")
	}

	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes) + ext, nil
}

func savePostImage(file *multipart.FileHeader) (string, error) {
	const maxFileSize = 5 << 20 // 5MB

	if file.Size > maxFileSize {
		return "", errors.New("image is too large. maximum size is 5MB")
	}

	uploadDir := "uploads"
	if err := os.MkdirAll(uploadDir, 0755); err != nil {
		return "", err
	}

	fileName, err := generateFileName(file.Filename)
	if err != nil {
		return "", errors.New("file name is invalid")
	}

	filePath := filepath.Join(uploadDir, fileName)

	src, err := file.Open()
	if err != nil {
		return "", err
	}
	defer src.Close()

	buffer := make([]byte, 512)
	n, err := io.ReadFull(src, buffer)
	if err != nil && err != io.ErrUnexpectedEOF {
		return "", err
	}

	contentType := http.DetectContentType(buffer[:n])
	allowedTypes := map[string]bool{
		"image/jpeg": true,
		"image/png":  true,
		"image/gif":  true,
		"image/webp": true,
	}
	if !allowedTypes[contentType] {
		return "", errors.New("content type is invalid")
	}

	if _, err := src.Seek(0, io.SeekStart); err != nil {
		return "", err
	}

	dst, err := os.Create(filePath)
	if err != nil {
		return "", err
	}
	defer dst.Close()

	if _, err := io.Copy(dst, src); err != nil {
		return "", err
	}

	return filePath, nil
}

func postIsVisibleTo(ctx context.Context, postID, userID int) (bool, error) {
	var visible bool

	err := db.QueryRow(
		ctx,
		`
		SELECT EXISTS (
			SELECT 1 FROM posts
			WHERE posts.id = $1
			AND (
				posts.is_private = false
				OR posts.author_id = $2
				OR EXISTS (
					SELECT 1 FROM post_shares
					WHERE post_shares.post_id = posts.id AND post_shares.user_id = $2
				)
			)
		)
		`,
		postID,
		userID,
	).Scan(&visible)

	return visible, err
}

type dbTX interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

func shareWithUsernames(ctx context.Context, tx dbTX, postID, ownerID int, usernamesCSV string) error {
	for _, username := range strings.Split(usernamesCSV, ",") {
		username = strings.TrimSpace(username)
		if username == "" {
			continue
		}

		var sharedUserID int

		err := tx.QueryRow(
			ctx,
			`SELECT id FROM users WHERE username = $1`,
			username,
		).Scan(&sharedUserID)
		if errors.Is(err, pgx.ErrNoRows) {
			return errors.New("User not found: " + username)
		}
		if err != nil {
			return err
		}

		if sharedUserID == ownerID {
			continue
		}

		_, err = tx.Exec(
			ctx,
			`INSERT INTO post_shares (post_id, user_id) VALUES ($1, $2) ON CONFLICT (post_id, user_id) DO NOTHING`,
			postID,
			sharedUserID,
		)
		if err != nil {
			return err
		}
	}

	return nil
}
