import { isAxiosError } from 'axios';

export function errorMessage(error: unknown, fallback: string): string {
  if (isAxiosError<{ detail?: string }>(error)) {
    return error.response?.data?.detail || error.message || fallback;
  }
  return error instanceof Error ? error.message : fallback;
}
