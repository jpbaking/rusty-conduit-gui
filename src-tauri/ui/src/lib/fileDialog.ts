// Native open and save dialogs, for fields that take a file path.

import { hasBackend } from "./api";

export interface FileFilter {
  name: string;
  extensions: string[];
}

export interface DialogOptions {
  title: string;
  /** A file name or full path to start from. */
  defaultPath?: string;
  filters?: FileFilter[];
}

/** Asks where to save a file. Resolves to the full path, or `null` if cancelled. */
export async function chooseSavePath(options: DialogOptions): Promise<string | null> {
  if (!hasBackend()) return previewPath(options);
  const { save } = await import("@tauri-apps/plugin-dialog");
  return save({ ...options, canCreateDirectories: true });
}

/** Asks for one existing file. Resolves to the full path, or `null` if cancelled. */
export async function chooseOpenPath(options: DialogOptions): Promise<string | null> {
  if (!hasBackend()) return previewPath(options);
  const { open } = await import("@tauri-apps/plugin-dialog");
  const picked = await open({ ...options, multiple: false, directory: false });
  return typeof picked === "string" ? picked : null;
}

/** The browser preview has no dialogs, so it picks a sample path. */
function previewPath(options: DialogOptions): string {
  const name = options.defaultPath?.split(/[\\/]/).pop() || "file";
  return `/Users/preview/Documents/${name}`;
}

/** Today's date as `YYYY-MM-DD`, for default file names. */
export function today(): string {
  const now = new Date();
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())}`;
}
