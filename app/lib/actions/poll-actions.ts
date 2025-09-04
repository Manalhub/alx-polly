"use server";

import { createClient } from "@/lib/supabase/server";
import { revalidatePath } from 'next/cache';

// Input validation and sanitization utilities
function sanitizeInput(input: string): string {
  return input.trim().replace(/[<>"'&]/g, '');
}

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

// CREATE POLL
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

// GET USER POLLS
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

// GET POLL BY ID
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

// SUBMIT VOTE
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

// DELETE POLL
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

// UPDATE POLL
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
