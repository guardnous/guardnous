"use client";

import React, { useEffect, useState, useCallback } from "react";
import { useSearchParams, useRouter } from "next/navigation";
import api from "@/lib/api";
import { Loader2, CheckCircle, AlertCircle } from "lucide-react";

function resolveProvider(params: URLSearchParams): string | null {
  // GitHub App flow
  if (params.get("installation_id")) return "github_app";
  // Provider stored in state as "provider:random_token"
  const state = params.get("state") || "";
  const parts = state.split(":");
  if (parts.length >= 2) return parts[0];
  return null;
}

export default function CallbackPage() {
  const searchParams = useSearchParams();
  const router = useRouter();
  const [status, setStatus] = useState<"processing" | "success" | "error">("processing");
  const [message, setMessage] = useState("");

  const handleCallback = useCallback(async () => {
    const installationId = searchParams.get("installation_id");
    const setupAction = searchParams.get("setup_action");
    const code = searchParams.get("code");
    const state = searchParams.get("state");
    const provider = resolveProvider(searchParams);

    if (installationId) {
      // GitHub App installation flow
      try {
        await api.post("/integrations/github/app/callback", {
          installation_id: installationId,
          setup_action: setupAction,
        });
        setStatus("success");
        setMessage("GitHub App installed successfully!");
        setTimeout(() => router.push("/integrations"), 2000);
      } catch {
        setStatus("error");
        setMessage("Failed to complete GitHub App installation");
      }
      return;
    }

    if (code && state && provider && provider !== "github_app") {
      // Generic OAuth callback — exchange code via backend
      try {
        await api.post(`/integrations/oauth/${provider}/callback`, {
          code,
          state,
        });
        const labels: Record<string, string> = {
          github: "GitHub",
          gitlab: "GitLab",
          bitbucket: "Bitbucket",
          azure_devops: "Azure DevOps",
        };
        setStatus("success");
        setMessage(`${labels[provider] || provider} connected successfully!`);
        setTimeout(() => router.push("/integrations"), 2000);
      } catch {
        setStatus("error");
        setMessage(`Failed to complete ${provider} OAuth authorization`);
      }
      return;
    }

    if (code) {
      setStatus("success");
      setMessage("OAuth authorization complete!");
      setTimeout(() => router.push("/integrations"), 2000);
      return;
    }

    setStatus("error");
    setMessage("Invalid callback parameters");
  }, [searchParams, router]);

  useEffect(() => {
    handleCallback();
  }, [handleCallback]);

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50 dark:bg-gray-900">
      <div className="text-center">
        {status === "processing" && (
          <>
            <Loader2 size={48} className="animate-spin text-orange-500 mx-auto mb-4" />
            <p className="text-lg text-gray-600 dark:text-gray-300">Processing...</p>
          </>
        )}
        {status === "success" && (
          <>
            <CheckCircle size={48} className="text-green-500 mx-auto mb-4" />
            <p className="text-lg text-gray-900 dark:text-white">{message}</p>
            <p className="text-sm text-gray-400 mt-2">Redirecting...</p>
          </>
        )}
        {status === "error" && (
          <>
            <AlertCircle size={48} className="text-red-500 mx-auto mb-4" />
            <p className="text-lg text-gray-900 dark:text-white">{message}</p>
            <button
              onClick={() => router.push("/integrations")}
              className="mt-4 px-4 py-2 bg-orange-500 text-white rounded-lg hover:bg-orange-600"
            >
              Back to Integrations
            </button>
          </>
        )}
      </div>
    </div>
  );
}
