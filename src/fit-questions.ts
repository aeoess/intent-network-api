// ══════════════════════════════════════════════════════════════
// Mingle v4 fit - vetted per-dimension question grammar (PUBLIC)
// ══════════════════════════════════════════════════════════════
// Questions are canonical renderings of a dimension, never free text authored by
// a counterparty. This is the safe form of "agents pick what to ask": the
// dimension graph is public, the phrasing is fixed, and nothing a counterparty
// wrote is rendered as a question. There are no card slots, so nothing a
// counterparty published can be injected here either.

export const DIMENSION_QUESTIONS: Record<string, string> = {
  weekly_commitment: 'Roughly how many hours a week could you commit?',
  start_window: 'When could you realistically start?',
  time_horizon: 'What time horizon are you picturing for this?',
  timezone: 'What timezone are you in, and how much live overlap do you need?',
  cadence: 'What working cadence suits you: async-first, mixed, or daily sync?',
  project_stage: 'What stage is the work at right now?',
  relationship_shape: 'What shape of working relationship are you looking for?',
  role_spike: 'What are you strongest at for this?',
  role_antiportfolio: 'What would you rather not own, or feel weaker at?',
  decision_model: 'How would you want decisions made between you?',
}

export function questionFor(dimension: string): string | null {
  return DIMENSION_QUESTIONS[dimension] ?? null
}
