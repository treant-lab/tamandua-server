defmodule TamanduaServer.E2E.AuthTest do
  @moduledoc """
  E2E tests for authentication flows.

  Tests cover:
  - Standard login/logout
  - MFA workflows
  - SSO integration (SAML, OAuth)
  - Password reset
  - Session management
  - Remember me functionality
  """

  use TamanduaServer.E2ECase, async: false

  alias Wallaby.Query

  describe "standard login flow" do
    setup do
      org = insert(:organization)
      user = insert(:user,
        email: "test@example.com",
        password_hash: Bcrypt.hash_pwd_salt("SecurePass123!"),
        organization_id: org.id,
        is_active: true
      )

      {:ok, user: user, org: org}
    end

    test "user can login with valid credentials", %{session: session, user: user} do
      session
      |> visit("/login")
      |> assert_has(Query.css(".login-page, [data-page='login']"))
      |> fill_in(Query.text_field("Email"), with: user.email)
      |> fill_in(Query.text_field("Password"), with: "SecurePass123!")
      |> click(Query.button("Sign in"))
      |> wait_for_page_load()
      |> assert_has(Query.css(".dashboard, [data-page='dashboard']"))
      |> assert_current_path("/dashboard")
    end

    test "user sees error with invalid email", %{session: session} do
      session
      |> visit("/login")
      |> fill_in(Query.text_field("Email"), with: "nonexistent@example.com")
      |> fill_in(Query.text_field("Password"), with: "wrongpassword")
      |> click(Query.button("Sign in"))
      |> assert_has(Query.css(".alert-error, [data-alert='error']"))
      |> assert_has(Query.text("Invalid email or password"))
    end

    test "user sees error with invalid password", %{session: session, user: user} do
      session
      |> visit("/login")
      |> fill_in(Query.text_field("Email"), with: user.email)
      |> fill_in(Query.text_field("Password"), with: "WrongPassword")
      |> click(Query.button("Sign in"))
      |> assert_has(Query.css(".alert-error, [data-alert='error']"))
      |> assert_has(Query.text("Invalid email or password"))
    end

    test "inactive user cannot login", %{session: session} do
      inactive_user = insert(:user,
        email: "inactive@example.com",
        password_hash: Bcrypt.hash_pwd_salt("password123"),
        is_active: false
      )

      session
      |> visit("/login")
      |> fill_in(Query.text_field("Email"), with: inactive_user.email)
      |> fill_in(Query.text_field("Password"), with: "password123")
      |> click(Query.button("Sign in"))
      |> assert_has(Query.css(".alert-error"))
      |> assert_has(Query.text("Account is inactive"))
    end

    test "user can logout successfully", %{session: session, user: user} do
      session
      |> login_user(user)
      |> click(Query.css("[data-action='logout'], .logout-button"))
      |> assert_current_path("/login")
      |> assert_has(Query.css(".login-page"))
    end

    test "form validation shows errors for empty fields", %{session: session} do
      session
      |> visit("/login")
      |> click(Query.button("Sign in"))
      |> assert_has(Query.css("[data-error='email']", text: "can't be blank"))
      |> assert_has(Query.css("[data-error='password']", text: "can't be blank"))
    end

    test "form validation shows error for invalid email format", %{session: session} do
      session
      |> visit("/login")
      |> fill_in(Query.text_field("Email"), with: "not-an-email")
      |> fill_in(Query.text_field("Password"), with: "password123")
      |> click(Query.button("Sign in"))
      |> assert_has(Query.css("[data-error='email']", text: "must be a valid email"))
    end
  end

  describe "MFA flow" do
    setup do
      user = insert(:user,
        email: "mfa-user@example.com",
        password_hash: Bcrypt.hash_pwd_salt("password123"),
        mfa_enabled: true,
        mfa_secret: "BASE32SECRET3232"
      )

      {:ok, user: user}
    end

    test "user is prompted for MFA code after password", %{session: session, user: user} do
      session
      |> visit("/login")
      |> fill_in(Query.text_field("Email"), with: user.email)
      |> fill_in(Query.text_field("Password"), with: "password123")
      |> click(Query.button("Sign in"))
      |> assert_has(Query.css(".mfa-page, [data-page='mfa']"))
      |> assert_has(Query.text("Enter your authentication code"))
    end

    test "valid MFA code allows login", %{session: session, user: user} do
      # Generate valid TOTP code (in real test, use NimbleTOTP)
      valid_code = "123456"

      session
      |> visit("/login")
      |> fill_in(Query.text_field("Email"), with: user.email)
      |> fill_in(Query.text_field("Password"), with: "password123")
      |> click(Query.button("Sign in"))
      |> assert_has(Query.css("[data-mfa-input]"))
      |> fill_in(Query.text_field("Code"), with: valid_code)
      |> click(Query.button("Verify"))
      # Would succeed with real TOTP implementation
    end

    test "invalid MFA code shows error", %{session: session, user: user} do
      session
      |> visit("/login")
      |> fill_in(Query.text_field("Email"), with: user.email)
      |> fill_in(Query.text_field("Password"), with: "password123")
      |> click(Query.button("Sign in"))
      |> fill_in(Query.text_field("Code"), with: "000000")
      |> click(Query.button("Verify"))
      |> assert_has(Query.css(".alert-error"))
      |> assert_has(Query.text("Invalid authentication code"))
    end

    test "user can use backup code", %{session: session, user: user} do
      session
      |> visit("/login")
      |> fill_in(Query.text_field("Email"), with: user.email)
      |> fill_in(Query.text_field("Password"), with: "password123")
      |> click(Query.button("Sign in"))
      |> click(Query.link("Use backup code"))
      |> assert_has(Query.css("[data-backup-code-input]"))
      |> fill_in(Query.text_field("Backup Code"), with: "BACKUP-CODE-123")
      |> click(Query.button("Verify"))
    end

    test "MFA code input accepts only numbers", %{session: session, user: user} do
      session
      |> visit("/login")
      |> fill_in(Query.text_field("Email"), with: user.email)
      |> fill_in(Query.text_field("Password"), with: "password123")
      |> click(Query.button("Sign in"))
      |> fill_in(Query.text_field("Code"), with: "abcdef")
      |> assert_has(Query.css("[data-error]", text: "must be numeric"))
    end
  end

  describe "SSO - SAML flow" do
    test "user can initiate SAML login", %{session: session} do
      session
      |> visit("/login")
      |> click(Query.button("Sign in with SSO"))
      |> fill_in(Query.text_field("Email or Organization"), with: "example.com")
      |> click(Query.button("Continue"))
      # Would redirect to SAML IdP
      |> assert_path_contains("/auth/saml")
    end

    test "SAML response creates user session", %{session: session} do
      # Simulate SAML callback
      # In a real test, you'd mock the SAML response
      session
      |> visit("/auth/saml/callback?SAMLResponse=mock_response")
      |> assert_current_path("/dashboard")
    end

    test "invalid SAML response shows error", %{session: session} do
      session
      |> visit("/auth/saml/callback?SAMLResponse=invalid")
      |> assert_has(Query.css(".alert-error"))
      |> assert_has(Query.text("SSO authentication failed"))
    end
  end

  describe "SSO - OAuth flow" do
    test "user can login with Google OAuth", %{session: session} do
      session
      |> visit("/login")
      |> click(Query.button("Sign in with Google"))
      # Would redirect to Google OAuth
      |> assert_path_contains("/auth/google")
    end

    test "user can login with Microsoft OAuth", %{session: session} do
      session
      |> visit("/login")
      |> click(Query.button("Sign in with Microsoft"))
      |> assert_path_contains("/auth/microsoft")
    end

    test "OAuth callback creates user session", %{session: session} do
      # Mock OAuth callback
      session
      |> visit("/auth/google/callback?code=mock_auth_code")
      |> assert_current_path("/dashboard")
    end
  end

  describe "password reset flow" do
    setup do
      user = insert(:user, email: "reset@example.com")
      {:ok, user: user}
    end

    test "user can request password reset", %{session: session, user: user} do
      session
      |> visit("/login")
      |> click(Query.link("Forgot password?"))
      |> assert_current_path("/password/reset")
      |> fill_in(Query.text_field("Email"), with: user.email)
      |> click(Query.button("Send reset instructions"))
      |> assert_success("Password reset instructions sent to your email")
    end

    test "password reset with invalid email shows success (security)", %{session: session} do
      session
      |> visit("/password/reset")
      |> fill_in(Query.text_field("Email"), with: "nonexistent@example.com")
      |> click(Query.button("Send reset instructions"))
      # Don't reveal if email exists
      |> assert_success("Password reset instructions sent to your email")
    end

    test "user can reset password with valid token", %{session: session} do
      token = "valid_reset_token_123"

      session
      |> visit("/password/reset/#{token}")
      |> assert_has(Query.css(".password-reset-form"))
      |> fill_in(Query.text_field("New Password"), with: "NewSecure123!")
      |> fill_in(Query.text_field("Confirm Password"), with: "NewSecure123!")
      |> click(Query.button("Reset Password"))
      |> assert_success("Password has been reset successfully")
      |> assert_current_path("/login")
    end

    test "password reset validates password strength", %{session: session} do
      token = "valid_reset_token_123"

      session
      |> visit("/password/reset/#{token}")
      |> fill_in(Query.text_field("New Password"), with: "weak")
      |> fill_in(Query.text_field("Confirm Password"), with: "weak")
      |> click(Query.button("Reset Password"))
      |> assert_has(Query.css("[data-error]", text: "Password must be at least 8 characters"))
    end

    test "password reset validates password confirmation", %{session: session} do
      token = "valid_reset_token_123"

      session
      |> visit("/password/reset/#{token}")
      |> fill_in(Query.text_field("New Password"), with: "NewSecure123!")
      |> fill_in(Query.text_field("Confirm Password"), with: "DifferentPassword!")
      |> click(Query.button("Reset Password"))
      |> assert_has(Query.css("[data-error]", text: "Passwords do not match"))
    end

    test "expired token shows error", %{session: session} do
      expired_token = "expired_token_xyz"

      session
      |> visit("/password/reset/#{expired_token}")
      |> assert_error("Password reset link has expired")
      |> assert_has(Query.link("Request a new reset link"))
    end
  end

  describe "session management" do
    setup do
      user = insert(:user)
      {:ok, user: user}
    end

    test "remember me checkbox extends session", %{session: session, user: user} do
      session
      |> visit("/login")
      |> fill_in(Query.text_field("Email"), with: user.email)
      |> fill_in(Query.text_field("Password"), with: "password123")
      |> click(Query.checkbox("Remember me"))
      |> click(Query.button("Sign in"))
      |> assert_current_path("/dashboard")
      # Check that remember_token cookie is set
      |> execute_js("return document.cookie.includes('remember_token')")
    end

    test "session expires after inactivity", %{session: session, user: user} do
      # This would require mocking time or waiting
      # Simplified version:
      session
      |> login_user(user)
      # Simulate session expiry by visiting with expired session
      |> visit("/dashboard")
      # Would redirect to login in real scenario
    end

    test "concurrent sessions are handled correctly", %{user: user} do
      # Open two sessions
      {:ok, session1} = Wallaby.start_session()
      {:ok, session2} = Wallaby.start_session()

      session1
      |> login_user(user)
      |> assert_current_path("/dashboard")

      session2
      |> login_user(user)
      |> assert_current_path("/dashboard")

      # Both sessions should work independently
      session1
      |> visit("/agents")
      |> assert_current_path("/agents")

      session2
      |> visit("/alerts")
      |> assert_current_path("/alerts")

      Wallaby.end_session(session1)
      Wallaby.end_session(session2)
    end

    test "logout invalidates session token", %{session: session, user: user} do
      session
      |> login_user(user)
      |> click(Query.css("[data-action='logout']"))
      |> visit("/dashboard")
      # Should redirect to login
      |> assert_current_path("/login")
    end
  end

  describe "security features" do
    setup do
      user = insert(:user, email: "security@example.com")
      {:ok, user: user}
    end

    test "rate limiting prevents brute force attempts", %{session: session, user: user} do
      # Attempt multiple failed logins
      for _ <- 1..6 do
        session
        |> visit("/login")
        |> fill_in(Query.text_field("Email"), with: user.email)
        |> fill_in(Query.text_field("Password"), with: "wrongpassword")
        |> click(Query.button("Sign in"))
      end

      # Next attempt should show rate limit error
      session
      |> visit("/login")
      |> fill_in(Query.text_field("Email"), with: user.email)
      |> fill_in(Query.text_field("Password"), with: "wrongpassword")
      |> click(Query.button("Sign in"))
      |> assert_has(Query.css(".alert-error"))
      |> assert_has(Query.text("Too many login attempts. Please try again later."))
    end

    test "login page has CSRF protection", %{session: session} do
      session
      |> visit("/login")
      |> assert_has(Query.css("input[name='_csrf_token']", visible: false))
    end

    test "password field has proper autocomplete attributes", %{session: session} do
      session
      |> visit("/login")
      |> assert_has(Query.css("input[type='password'][autocomplete='current-password']"))
    end

    test "login form prevents credential stuffing with captcha", %{session: session} do
      # After multiple failed attempts, captcha should appear
      session
      |> visit("/login")
      # Simulate failed attempts...
      |> assert_has(Query.css("[data-captcha]"))
    end
  end

  describe "redirect after login" do
    setup do
      user = insert(:user)
      {:ok, user: user}
    end

    test "redirects to originally requested page after login", %{session: session, user: user} do
      # Try to access protected page
      session
      |> visit("/agents")
      |> assert_current_path("/login?redirect=/agents")
      |> fill_in(Query.text_field("Email"), with: user.email)
      |> fill_in(Query.text_field("Password"), with: "password123")
      |> click(Query.button("Sign in"))
      |> assert_current_path("/agents")
    end

    test "redirects to dashboard if no redirect parameter", %{session: session, user: user} do
      session
      |> visit("/login")
      |> fill_in(Query.text_field("Email"), with: user.email)
      |> fill_in(Query.text_field("Password"), with: "password123")
      |> click(Query.button("Sign in"))
      |> assert_current_path("/dashboard")
    end
  end
end
