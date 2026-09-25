// Smoke test for Vercel AI Gateway through the AI SDK.
// Needs AI_GATEWAY_API_KEY in .env.local (git-ignored). Run: npm run example
import { generateText } from 'ai';

const { text } = await generateText({
  model: 'openai/gpt-5.5',
  prompt: 'Invent a new holiday and describe its traditions.',
});

console.log(text);
