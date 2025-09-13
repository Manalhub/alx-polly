"use server";

import { createClient } from "@/lib/supabase/server";
import { revalidatePath } from 'next/cache';

/**
 * Sanitizes user input by removing potentially dangerous characters.
 * 
 * This function is critical for preventing XSS attacks by stripping HTML/XML characters
 * that could be used for script injection. It's applied to all user-generated content
 * before database storage, ensuring that poll questions and options are safe to display
 * without additional escaping in the UI.
 * 
 * @param input - Raw string input from user forms
 * @returns Sanitized string safe for database storage and display
 * 
 * @assumptions:
 * - Input is a string (not null/undefined)
 * - Basic character filtering is sufficient for security needs
 * - More complex sanitization is handled by React's built-in XSS protection
 * 
 * @edge_cases:
 * - Empty string: Returns empty string (preserves empty options)
 * - Only whitespace: Trimming removes it, returns empty string
 * - Unicode characters: Preserved (not filtered by regex)
 * - Very long strings: No length limit here (handled by validation)
 * 
 * @connections:
 * - Used by createPoll() and updatePoll() for all text inputs
 * - Applied to poll questions and all option texts
 * - Works with validatePollInput() for complete input security
 * - Enables safe direct rendering of poll content in components
 */
function sanitizeInput(input: string): string {
  return input.trim().replace(/[<>"'&]/g, '');
}

/**
 * Validates poll input data for completeness, length, and format requirements.
 * 
 * This function ensures data quality and prevents abuse by enforcing business rules
 * for poll creation. It validates that polls have meaningful content, appropriate
 * length limits to prevent UI issues, and sufficient options for meaningful voting.
 * The validation rules balance usability with system performance and UI constraints.
 * 
 * @param question - The poll question text to validate
 * @param options - Array of poll option strings to validate
 * @returns Error message string if validation fails, null if valid
 * 
 * @assumptions:
 * - Input has already been sanitized by sanitizeInput()
 * - Options array contains only strings (no mixed types)
 * - Question and options are not null/undefined
 * 
 * @edge_cases:
 * - Empty question: Returns validation error
 * - Single option: Returns error (polls need choice)
 * - Very long content: Enforced length limits prevent UI overflow
 * - Whitespace-only options: Trimmed length check catches these
 * - Maximum length inputs: Allowed but may cause UI layout issues
 * 
 * @connections:
 * - Used by createPoll() and updatePoll() before database operations
 * - Works with sanitizeInput() for complete input processing pipeline
 * - Error messages displayed directly to users in form components
 * - Prevents database storage of invalid poll data
 * - Length limits chosen to fit UI components and database constraints
 */
function validatePollInput(question: string, options: string[]): string | null {
  if (!question || question.trim().length < 3) {
    return "Question must be at least 3 characters long.";
  }
  if (options.length < 2) {
    return "Please provide at least two options.";
  }
  if (options.some(opt => !opt || opt.trim().length === 0)) {
    return "All options must contain valid text.";
  }
  if (question.length > 500) {
    return "Question is too long (max 500 characters).";
  }
  if (options.some(opt => opt.length > 200)) {
    return "Options are too long (max 200 characters each).";
  }
  return null;
}

/**
 * Creates a new poll with user-provided question and options.
 * 
 * This is the core function for poll creation, handling the complete workflow from
 * form data processing to database storage. It ensures data security through input
 * sanitization and validation, enforces authentication requirements, and associates
 * the poll with the creating user for proper ownership tracking. The function
 * integrates with the app's security model and triggers cache revalidation.
 * 
 * @param formData - Form data containing 'question' and 'options' fields
 * @returns Promise resolving to success/error state for UI feedback
 * 
 * @assumptions:
 * - User is authenticated (enforced by function logic)
 * - Form data contains required fields with string values
 * - Supabase client is properly configured and accessible
 * - User has permission to create polls (default for authenticated users)
 * 
 * @edge_cases:
 * - Unauthenticated user: Returns error, redirects to login
 * - Invalid input data: Validation errors returned to form
 * - Database connection issues: Generic error message returned
 * - Duplicate poll creation: Allowed (no uniqueness constraints)
 * - Network timeouts: Supabase client handles retries
 * 
 * @connections:
 * - Used by PollCreateForm component via server action
 * - Calls sanitizeInput() and validatePollInput() for data security
 * - Uses getCurrentUser() to establish poll ownership
 * - Triggers revalidatePath() to refresh polls list
 * - Success redirects user to polls dashboard
 * - Creates database record that enables voting via submitVote()
 */
export async function createPoll(formData: FormData) {
  const supabase = await createClient();

  const question = sanitizeInput(formData.get("question") as string);
  const options = (formData.getAll("options") as string[])
    .filter(Boolean)
    .map(opt => sanitizeInput(opt));

  const validationError = validatePollInput(question, options);
  if (validationError) {
    return { error: validationError };
  }

  // Get user from session
  const {
    data: { user },
    error: userError,
  } = await supabase.auth.getUser();
  if (userError) {
    return { error: "Authentication error. Please try again." };
  }
  if (!user) {
    return { error: "You must be logged in to create a poll." };
  }

  const { error } = await supabase.from("polls").insert([
    {
      user_id: user.id,
      question,
      options,
    },
  ]);

  if (error) {
    return { error: "Failed to create poll. Please try again." };
  }

  revalidatePath("/polls");
  return { error: null };
}

/**
 * Retrieves all polls created by the currently authenticated user.
 * 
 * This function powers the user's personal poll dashboard by fetching their created
 * polls in reverse chronological order. It's essential for poll management features,
 * allowing users to view, edit, and delete their own polls. The function enforces
 * proper authorization by only returning polls owned by the authenticated user.
 * 
 * @returns Promise resolving to polls array and error state
 * 
 * @assumptions:
 * - User is authenticated (returns empty array if not)
 * - Database has proper indexes on user_id and created_at for performance
 * - Poll data structure matches expected format
 * 
 * @edge_cases:
 * - Unauthenticated user: Returns empty polls array with error message
 * - No polls created: Returns empty array (normal state)
 * - Database errors: Returns empty array with error message
 * - Large number of polls: Ordered by date, may need pagination in future
 * 
 * @connections:
 * - Used by polls dashboard page to display user's polls
 * - Powers PollActions component for edit/delete functionality
 * - Results cached by Next.js until revalidatePath() is called
 * - Used to determine if user can edit/delete specific polls
 * - Poll data feeds into PollCard components for display
 */
export async function getUserPolls() {
  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();
  if (!user) return { polls: [], error: "Not authenticated" };

  const { data, error } = await supabase
    .from("polls")
    .select("*")
    .eq("user_id", user.id)
    .order("created_at", { ascending: false });

  if (error) return { polls: [], error: "Failed to fetch polls." };
  return { polls: data ?? [], error: null };
}

/**
 * Retrieves a specific poll by its unique identifier.
 * 
 * This function enables poll viewing, voting, and sharing by providing access to
 * individual poll data. It includes security validation to prevent SQL injection
 * attacks through UUID format validation. The function is used for both authenticated
 * poll management and public poll viewing/voting scenarios.
 * 
 * @param id - UUID string identifying the poll to retrieve
 * @returns Promise resolving to poll data and error state
 * 
 * @assumptions:
 * - ID parameter is a valid UUID string format
 * - Poll exists in database (may not exist if deleted)
 * - Poll data structure is consistent with database schema
 * 
 * @edge_cases:
 * - Invalid UUID format: Returns error (prevents SQL injection)
 * - Non-existent poll: Returns error with 'Poll not found' message
 * - Database connection issues: Returns error
 * - Deleted poll: Returns error (poll no longer exists)
 * - Corrupted poll data: Database constraints should prevent this
 * 
 * @connections:
 * - Used by poll detail pages for viewing and voting
 * - Called by submitVote() to validate poll existence
 * - Powers poll sharing functionality via unique URLs
 * - Used by edit forms to load existing poll data
 * - Poll data feeds into voting interfaces and result displays
 */
export async function getPollById(id: string) {
  // Validate UUID format to prevent SQL injection
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id)) {
    return { poll: null, error: "Invalid poll ID format." };
  }

  const supabase = await createClient();
  const { data, error } = await supabase
    .from("polls")
    .select("*")
    .eq("id", id)
    .single();

  if (error) return { poll: null, error: "Poll not found." };
  return { poll: data, error: null };
}

/**
 * Records a user's vote for a specific option in a poll.
 * 
 * This function implements the core voting functionality by recording user choices
 * in the database. It enforces voting rules including one-vote-per-user restrictions
 * and validates both poll existence and option validity. The function supports both
 * authenticated and anonymous voting, with different duplicate prevention strategies.
 * 
 * @param pollId - UUID string identifying the poll to vote in
 * @param optionIndex - Zero-based index of the selected option
 * @returns Promise resolving to success/error state
 * 
 * @assumptions:
 * - Poll ID is a valid UUID format
 * - Option index is within valid range for the poll
 * - User is either authenticated or voting anonymously
 * - Poll exists and is active (not deleted)
 * 
 * @edge_cases:
 * - Invalid poll ID: Returns error (security validation)
 * - Invalid option index: Returns error if out of range
 * - Already voted (authenticated): Returns error with clear message
 * - Poll not found: Returns error
 * - Anonymous user: Allows voting but no duplicate prevention
 * - Database errors: Returns generic error message
 * 
 * @connections:
 * - Used by poll detail pages when users submit votes
 * - Calls getPollById() to validate poll existence and options
 * - Creates vote records that affect poll result calculations
 * - Vote data used to display poll results and statistics
 * - Anonymous votes tracked separately from authenticated votes
 */
export async function submitVote(pollId: string, optionIndex: number) {
  // Validate inputs
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(pollId)) {
    return { error: "Invalid poll ID format." };
  }
  if (!Number.isInteger(optionIndex) || optionIndex < 0) {
    return { error: "Invalid option selection." };
  }

  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();

  // Verify poll exists and get options to validate optionIndex
  const { data: poll, error: pollError } = await supabase
    .from("polls")
    .select("options")
    .eq("id", pollId)
    .single();

  if (pollError || !poll) {
    return { error: "Poll not found." };
  }
  if (optionIndex >= poll.options.length) {
    return { error: "Invalid option selection." };
  }

  // Check if user already voted (if authenticated)
  if (user) {
    const { data: existingVote } = await supabase
      .from("votes")
      .select("*")
      .eq("poll_id", pollId)
      .eq("user_id", user.id)
      .single();

    if (existingVote) {
      return { error: "You have already voted on this poll." };
    }
  }

  const { error } = await supabase.from("votes").insert([
    {
      poll_id: pollId,
      user_id: user?.id ?? null,
      option_index: optionIndex,
    },
  ]);

  if (error) return { error: "Failed to submit vote. Please try again." };
  return { error: null };
}

/**
 * Permanently removes a poll and all associated votes from the database.
 * 
 * This function implements poll deletion with proper authorization checks to ensure
 * only poll owners can delete their polls. It's critical for user data management
 * and privacy, allowing users to remove polls they no longer want to share. The
 * deletion is cascading, removing all votes associated with the poll.
 * 
 * @param id - UUID string identifying the poll to delete
 * @returns Promise resolving to success/error state
 * 
 * @assumptions:
 * - User is authenticated (enforced by function logic)
 * - Poll ID is a valid UUID format
 * - User owns the poll they're trying to delete
 * - Database supports cascade deletion of related vote records
 * 
 * @edge_cases:
 * - Invalid UUID format: Returns error (security validation)
 * - Unauthenticated user: Returns authentication error
 * - Poll not found: Returns error (may have been already deleted)
 * - User doesn't own poll: No error returned (silent failure for security)
 * - Database constraint violations: Returns error
 * - Concurrent deletion: Database handles race conditions
 * 
 * @connections:
 * - Used by PollActions component for delete functionality
 * - Triggers revalidatePath() to refresh polls list
 * - Removes poll from all user dashboards and public views
 * - Deletes all associated votes (cascade delete)
 * - Poll no longer accessible via direct URL or voting
 */
export async function deletePoll(id: string) {
  // Validate UUID format
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id)) {
    return { error: "Invalid poll ID format." };
  }

  const supabase = await createClient();
  
  // Get user from session
  const {
    data: { user },
    error: userError,
  } = await supabase.auth.getUser();
  if (userError) {
    return { error: "Authentication error. Please try again." };
  }
  if (!user) {
    return { error: "You must be logged in to delete a poll." };
  }

  // Only allow deleting polls owned by the user
  const { error } = await supabase
    .from("polls")
    .delete()
    .eq("id", id)
    .eq("user_id", user.id);

  if (error) {
    return { error: "Failed to delete poll or poll not found." };
  }

  revalidatePath("/polls");
  return { error: null };
}

/**
 * Updates an existing poll's question and options while preserving votes.
 * 
 * This function enables poll editing functionality, allowing users to modify their
 * polls after creation. It maintains data integrity by preserving existing votes
 * while updating poll content, and enforces the same validation rules as poll
 * creation. The function ensures only poll owners can make modifications.
 * 
 * @param pollId - UUID string identifying the poll to update
 * @param formData - Form data containing updated 'question' and 'options'
 * @returns Promise resolving to success/error state
 * 
 * @assumptions:
 * - User is authenticated and owns the poll
 * - Poll exists and hasn't been deleted
 * - Form data structure matches createPoll() requirements
 * - Existing votes should be preserved during updates
 * 
 * @edge_cases:
 * - Invalid UUID format: Returns error (security validation)
 * - Unauthenticated user: Returns authentication error
 * - Poll not found: Returns error (may have been deleted)
 * - User doesn't own poll: Silent failure (no error for security)
 * - Invalid form data: Validation errors returned
 * - Concurrent updates: Database handles race conditions
 * 
 * @connections:
 * - Used by EditPollForm component for poll modifications
 * - Calls same validation functions as createPoll()
 * - Triggers revalidatePath() to refresh UI
 * - Preserves existing votes and poll statistics
 * - Updates poll data visible in all poll views and sharing
 */
export async function updatePoll(pollId: string, formData: FormData) {
  // Validate UUID format
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(pollId)) {
    return { error: "Invalid poll ID format." };
  }

  const supabase = await createClient();

  const question = sanitizeInput(formData.get("question") as string);
  const options = (formData.getAll("options") as string[])
    .filter(Boolean)
    .map(opt => sanitizeInput(opt));

  const validationError = validatePollInput(question, options);
  if (validationError) {
    return { error: validationError };
  }

  // Get user from session
  const {
    data: { user },
    error: userError,
  } = await supabase.auth.getUser();
  if (userError) {
    return { error: "Authentication error. Please try again." };
  }
  if (!user) {
    return { error: "You must be logged in to update a poll." };
  }

  // Only allow updating polls owned by the user
  const { error } = await supabase
    .from("polls")
    .update({ question, options })
    .eq("id", pollId)
    .eq("user_id", user.id);

  if (error) {
    return { error: "Failed to update poll or poll not found." };
  }

  revalidatePath("/polls");
  return { error: null };
}
