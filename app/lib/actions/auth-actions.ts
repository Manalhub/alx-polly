'use server';

import { createClient } from '@/lib/supabase/server';
import { LoginFormData, RegisterFormData } from '../types';

/**
 * Authenticates a user with email and password credentials.
 * 
 * This function is critical for the app's security model as it establishes user sessions
 * that control access to poll creation, voting, and management features. It connects to
 * Supabase's authentication system which handles session management, token validation,
 * and secure credential verification.
 * 
 * @param data - Contains email and password from the login form
 * @returns Promise resolving to success/error state
 * 
 * @assumptions:
 * - User credentials are valid and exist in Supabase auth system
 * - Supabase client is properly configured with environment variables
 * - Email format validation is handled by the form layer
 * 
 * @edge_cases:
 * - Invalid credentials: Returns error message for display
 * - Network failures: Supabase client handles retries and timeouts
 * - Account locked/disabled: Error message indicates account status
 * 
 * @connections:
 * - Used by LoginPage component for form submission
 * - Triggers session creation that affects AuthContext state
 * - Success redirects user to /polls dashboard
 * - Session state determines access to protected routes via middleware
 */
export async function login(data: LoginFormData) {
  const supabase = await createClient();

  const { error } = await supabase.auth.signInWithPassword({
    email: data.email,
    password: data.password,
  });

  if (error) {
    return { error: error.message };
  }

  // Success: no error
  return { error: null };
}

/**
 * Creates a new user account with email, password, and name.
 * 
 * This function enables new users to join the polling platform by creating accounts
 * in Supabase's authentication system. It's essential for user onboarding and ensures
 * each poll creator can be uniquely identified and their polls can be properly attributed.
 * The user metadata (name) is stored for display purposes in the UI.
 * 
 * @param data - Contains name, email, and password from registration form
 * @returns Promise resolving to success/error state
 * 
 * @assumptions:
 * - Email is unique and not already registered
 * - Password meets Supabase's security requirements (handled client-side)
 * - Name is provided and not empty
 * - Email confirmation is not required (app setting)
 * 
 * @edge_cases:
 * - Duplicate email: Returns error message indicating email already exists
 * - Weak password: Supabase enforces password policies, returns specific error
 * - Network issues: Error handling ensures user gets feedback
 * - Invalid email format: Supabase validation catches this
 * 
 * @connections:
 * - Used by RegisterPage component for account creation
 * - Creates user record that enables poll creation via createPoll()
 * - Establishes user identity for poll ownership verification
 * - Success redirects to /polls dashboard (same as login)
 * - User metadata is available via getCurrentUser() for UI display
 */
export async function register(data: RegisterFormData) {
  const supabase = await createClient();

  const { error } = await supabase.auth.signUp({
    email: data.email,
    password: data.password,
    options: {
      data: {
        name: data.name,
      },
    },
  });

  if (error) {
    return { error: error.message };
  }

  // Success: no error
  return { error: null };
}

/**
 * Terminates the current user session and clears authentication state.
 * 
 * This function is essential for security as it properly cleans up user sessions,
 * ensuring that sensitive data and access privileges are revoked when users finish
 * their session. It's particularly important for shared devices and security compliance.
 * The logout process clears both server-side session tokens and client-side auth state.
 * 
 * @returns Promise resolving to success/error state
 * 
 * @assumptions:
 * - User has an active session to terminate
 * - Supabase client is properly initialized
 * - No ongoing critical operations that require authentication
 * 
 * @edge_cases:
 * - No active session: Still returns success (idempotent operation)
 * - Network failures: May leave client-side state inconsistent
 * - Concurrent logout attempts: Supabase handles gracefully
 * 
 * @connections:
 * - Used by header/navigation components for logout functionality
 * - Triggers AuthContext state change (user becomes null)
 * - Redirects user to login page or home page after logout
 * - Clears any cached user data in client components
 * - Middleware will redirect protected routes to login
 */
export async function logout() {
  const supabase = await createClient();
  const { error } = await supabase.auth.signOut();
  if (error) {
    return { error: error.message };
  }
  return { error: null };
}

/**
 * Retrieves the currently authenticated user's information.
 * 
 * This function provides access to the current user's profile data, which is essential
 * for personalizing the UI, enforcing authorization rules, and associating user actions
 * with their identity. It's used throughout the app to determine what content to show
 * and what actions the user is permitted to perform.
 * 
 * @returns Promise resolving to User object or null if not authenticated
 * 
 * @assumptions:
 * - Supabase client is properly configured with valid session
 * - User session is active and not expired
 * - User metadata is properly stored during registration
 * 
 * @edge_cases:
 * - No active session: Returns null (handled gracefully by callers)
 * - Expired session: Returns null, should trigger re-authentication
 * - Network issues: May return null, components should handle loading states
 * - User metadata missing: Returns user with minimal info (id, email)
 * 
 * @connections:
 * - Used by AuthContext to maintain user state across the app
 * - Enables poll ownership checks in createPoll(), deletePoll(), updatePoll()
 * - Powers conditional UI rendering (show/hide admin features)
 * - Used by middleware to determine route access permissions
 * - Provides user name for display in navigation and poll attribution
 */
export async function getCurrentUser() {
  const supabase = await createClient();
  const { data } = await supabase.auth.getUser();
  return data.user;
}

/**
 * Retrieves the current authentication session information.
 * 
 * This function provides access to the full session object, including tokens and
 * expiration information. It's used for session validation, token refresh operations,
 * and determining session state for middleware and route protection. Unlike getCurrentUser(),
 * this returns the complete session object rather than just user data.
 * 
 * @returns Promise resolving to Session object or null if no active session
 * 
 * @assumptions:
 * - Supabase client is properly configured
 * - Session tokens are valid and not corrupted
 * - System clock is synchronized (for token expiration checks)
 * 
 * @edge_cases:
 * - No active session: Returns null (normal for logged-out users)
 * - Expired session: Returns null, triggers re-authentication flow
 * - Malformed tokens: Supabase handles validation and returns null
 * - Network issues: May return null, should be handled gracefully
 * 
 * @connections:
 * - Used by middleware for route protection decisions
 * - Powers AuthContext session state management
 * - Enables token refresh operations before expiration
 * - Used by server components to verify authentication status
 * - Session expiration triggers automatic logout and redirect to login
 */
export async function getSession() {
  const supabase = await createClient();
  const { data } = await supabase.auth.getSession();
  return data.session;
}
